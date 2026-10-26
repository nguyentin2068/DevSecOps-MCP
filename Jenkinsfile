// DevSecOps pipeline example: scanners run directly via the devsecops-scan CLI inside the
// scanner image; results are stored as JSON + SARIF; the build is gated on the CLI exit code.
//
// Required plugins: Pipeline, Docker Pipeline, Timestamper, Warnings Next Generation (SARIF),
// Credentials Binding (AI triage and DefectDojo stages).
//
// Optional stages, enabled by Jenkins global (or node) environment variables:
// - AI triage: ANTHROPIC_CREDENTIALS_ID = id of a "Secret text" credential holding an Anthropic
//   API key. Without it, the stage still correlates findings, without AI.
// - DefectDojo: DEFECTDOJO_URL and DEFECTDOJO_CREDENTIALS_ID ("Secret text" with an API v2 key).
//   Optional: DEFECTDOJO_PRODUCT (default: the repository/job name), DEFECTDOJO_PRODUCT_TYPE.
// Both are advisory: a failure marks the build UNSTABLE, and the gate never uses their output.
// Setup walkthrough: docs/DEPLOYMENT-GUIDE.md (single-machine lab: docs/JENKINS-SETUP.md).
// On Kubernetes, replace the docker agent with the pod template in
// deploy/k8s/jenkins/scanner-pod.yaml (see the comment at the agent block).
//
// CLI exit codes: 0 pass/warn, 1 policy fail, 2 scanner/usage/config error.

pipeline {
  agent {
    docker {
      image(params.SCANNER_IMAGE ?: 'registry.example.com/devsecops-scanner:2.1.0')
    }
    // Kubernetes alternative:
    // kubernetes { yamlFile 'deploy/k8s/jenkins/scanner-pod.yaml'; defaultContainer 'scanner' }
  }

  parameters {
    string(name: 'SCANNER_IMAGE', defaultValue: 'registry.example.com/devsecops-scanner:2.1.0', description: 'Scanner image built with: docker build --target scanner')
    string(name: 'IMAGE_REF', defaultValue: '', description: 'Container image to scan with Trivy (optional), e.g. registry.example.com/app:1.2.3')
    string(name: 'DAST_TARGET_URL', defaultValue: '', description: 'Staging URL to crawl (katana) and scan (nuclei); optional, must pass the DAST allowlist')
    choice(name: 'DAST_MODE', choices: ['baseline', 'full'], description: 'full adds nuclei fuzzing templates; use only against test environments')
  }

  options {
    timestamps()
    timeout(time: 90, unit: 'MINUTES')
    buildDiscarder(logRotator(numToKeepStr: '30', artifactNumToKeepStr: '10'))
  }

  environment {
    // Scans may only read inside the workspace; results land in ./security-reports.
    SCAN_WORKSPACE_ROOTS = "${env.WORKSPACE}"
    REPORTS_DIR = "${env.WORKSPACE}/security-reports"
    HOME = "${env.WORKSPACE}@tmp/home"
    // Kept in the job's @tmp dir so the Trivy DB survives between builds on the same agent.
    TRIVY_CACHE_DIR = "${env.WORKSPACE}@tmp/trivy-cache"
    // To keep the policy in the application repo, commit it and point here instead:
    // SECURITY_RULES_PATH = "${env.WORKSPACE}/.devsecops/security-rules.yml"
  }

  stages {
    stage('Prepare') {
      steps {
        script {
          // Unique, valid scan id prefix: lowercase [a-z0-9_-] only, short enough for every id.
          def prefix = "${env.JOB_NAME}-${env.BUILD_NUMBER}".toLowerCase().replaceAll('[^a-z0-9_-]', '-')
          env.SCAN_PREFIX = prefix.length() > 90 ? prefix.substring(prefix.length() - 90) : prefix

          // Every scan this build runs, as CLI arguments for the triage, DefectDojo and gate stages.
          def ids = ["sast-opengrep-${env.SCAN_PREFIX}", "sca-osv-scanner-${env.SCAN_PREFIX}", "sca-trivy-${env.SCAN_PREFIX}"]
          if (params.IMAGE_REF?.trim()) { ids << "container-trivy-${env.SCAN_PREFIX}" }
          if (params.DAST_TARGET_URL?.trim()) { ids << "dast-nuclei-${env.SCAN_PREFIX}" }
          env.SCAN_ID_ARGS = ids.collect { "--scan-id ${it}" }.join(' ')
        }
        sh 'mkdir -p "$HOME" "$REPORTS_DIR" "$TRIVY_CACHE_DIR"'
      }
    }

    stage('Pre-check: detect languages') {
      // Finds the languages in the checked-out code from file extensions. The per-language
      // table is printed to the console; stdout is the comma-separated list of languages that
      // have rules in the policy (sast.opengrep.language_configs), which the SAST stage scans.
      // The full detection is archived with the reports.
      steps {
        script {
          env.SCAN_LANGUAGES = sh(
            returnStdout: true,
            script: 'devsecops-scan detect --target . --out "$REPORTS_DIR/languages-$SCAN_PREFIX.json"'
          ).trim()
          echo "SAST languages: ${env.SCAN_LANGUAGES ?: 'none detected (common rules only)'}"
        }
      }
    }

    stage('Scans') {
      // --no-fail records results without failing the stage, so every scanner runs and the
      // single gate below decides the build. A scanner error still exits 2 and fails the stage.
      parallel {
        stage('SAST: Opengrep') {
          steps {
            // Only the rule sets for the detected languages, plus the common rules (secrets, baseline).
            sh 'devsecops-scan sast --tool opengrep --target . --languages "$SCAN_LANGUAGES" --scan-id "sast-opengrep-$SCAN_PREFIX" --no-fail'
          }
        }
        stage('SCA: OSV-Scanner') {
          steps {
            sh 'devsecops-scan sca --tool osv-scanner --target . --scan-id "sca-osv-scanner-$SCAN_PREFIX" --no-fail'
          }
        }
        stage('SCA: Trivy fs') {
          steps {
            sh 'devsecops-scan sca --tool trivy --target . --scan-id "sca-trivy-$SCAN_PREFIX" --no-fail'
          }
        }
        stage('Container: Trivy image') {
          when { expression { params.IMAGE_REF?.trim() } }
          steps {
            withEnv(["IMAGE_REF=${params.IMAGE_REF.trim()}"]) {
              sh 'devsecops-scan container --target "$IMAGE_REF" --scan-id "container-trivy-$SCAN_PREFIX" --no-fail'
            }
          }
        }
      }
    }

    stage('DAST: Katana + Nuclei') {
      when { expression { params.DAST_TARGET_URL?.trim() } }
      steps {
        withEnv(["DAST_TARGET_URL=${params.DAST_TARGET_URL.trim()}", "DAST_MODE=${params.DAST_MODE ?: 'baseline'}"]) {
          sh 'devsecops-scan dast --target "$DAST_TARGET_URL" --dast-mode "$DAST_MODE" --scan-id "dast-nuclei-$SCAN_PREFIX" --no-fail'
        }
      }
    }

    stage('AI triage + correlate') {
      // Groups findings that describe the same issue across tools (same CVE, same line and CWE,
      // same endpoint), then asks Claude for an advisory verdict per group when an Anthropic
      // credential is configured. Output: security-reports/triage-<prefix>.json and .md.
      steps {
        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
          script {
            if (env.ANTHROPIC_CREDENTIALS_ID?.trim()) {
              withCredentials([string(credentialsId: env.ANTHROPIC_CREDENTIALS_ID, variable: 'ANTHROPIC_API_KEY')]) {
                sh 'devsecops-scan triage $SCAN_ID_ARGS --out "$REPORTS_DIR/triage-$SCAN_PREFIX.json" --md "$REPORTS_DIR/triage-$SCAN_PREFIX.md"'
              }
            } else {
              sh 'devsecops-scan triage $SCAN_ID_ARGS --no-ai --out "$REPORTS_DIR/triage-$SCAN_PREFIX.json" --md "$REPORTS_DIR/triage-$SCAN_PREFIX.md"'
            }
          }
        }
      }
    }

    stage('DefectDojo import') {
      // One DefectDojo test per tool, reimported every build (closes fixed findings), in the
      // product for this repository and an engagement per branch. AI verdicts and correlation
      // become tags (ai-*, corr-*). Failed scans are skipped so their findings stay open.
      when { expression { env.DEFECTDOJO_URL?.trim() && env.DEFECTDOJO_CREDENTIALS_ID?.trim() } }
      steps {
        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
          script {
            // Multibranch jobs are named <folder>/<repo>/<branch>: use the repo; plain jobs: the job name.
            def parts = env.JOB_NAME.split('/')
            def product = env.DEFECTDOJO_PRODUCT?.trim() ?: ((env.BRANCH_NAME && parts.length > 1) ? parts[-2] : parts[-1])
            def branch = env.BRANCH_NAME ?: (env.GIT_BRANCH ?: 'main').replaceFirst('^origin/', '')
            withEnv([
              "DD_PRODUCT=${product}",
              "DD_PRODUCT_TYPE=${env.DEFECTDOJO_PRODUCT_TYPE?.trim() ?: 'DevSecOps'}",
              "DD_ENGAGEMENT=CI/CD ${branch}",
              "DD_BRANCH=${branch}"
            ]) {
              withCredentials([string(credentialsId: env.DEFECTDOJO_CREDENTIALS_ID, variable: 'DEFECTDOJO_API_KEY')]) {
                sh '''
                  set -eu
                  triage="$REPORTS_DIR/triage-$SCAN_PREFIX.json"
                  [ -f "$triage" ] && set -- --triage "$triage" || set --
                  devsecops-scan defectdojo $SCAN_ID_ARGS "$@" \
                    --product "$DD_PRODUCT" --product-type "$DD_PRODUCT_TYPE" --engagement "$DD_ENGAGEMENT" \
                    --branch "$DD_BRANCH" --commit "${GIT_COMMIT:-}" --build-id "$BUILD_NUMBER" ${GIT_URL:+--scm-uri "$GIT_URL"}
                '''
              }
            }
          }
        }
      }
    }

    stage('Security gate') {
      steps {
        sh 'devsecops-scan report $SCAN_ID_ARGS --format markdown --out "security-reports/summary-$SCAN_PREFIX.md"'
        // Exit 1 (policy FAIL) or 2 (missing/broken results) fails the build here. The gate
        // reads the raw scan results only; triage verdicts never change it.
        sh 'devsecops-scan gate $SCAN_ID_ARGS'
      }
    }
  }

  post {
    always {
      // Optional: hand this build's results to the MCP server. Set MCP_REPORTS_DIR (Jenkins
      // global or node environment variable) to a directory the agent can write and the MCP
      // server mounts read-only; see docs/DEPLOYMENT-GUIDE.md. Each scan directory is copied
      // under a temporary name and renamed, so the MCP server never sees a partial result.
      script {
        if (env.MCP_REPORTS_DIR?.trim()) {
          sh '''
            set -eu
            [ -n "${SCAN_PREFIX:-}" ] || exit 0
            for dir in security-reports/*-"$SCAN_PREFIX"; do
              [ -d "$dir" ] || continue
              dest="$MCP_REPORTS_DIR/$(basename "$dir")"
              [ -e "$dest" ] && continue
              cp -R "$dir" "$dest.partial.$$" && mv "$dest.partial.$$" "$dest"
            done
          '''
        }
      }
      archiveArtifacts artifacts: 'security-reports/**', allowEmptyArchive: true, fingerprint: true
      recordIssues(
        enabledForFailure: true,
        aggregatingResults: false,
        tools: [sarif(pattern: 'security-reports/**/result.sarif', id: 'devsecops', name: 'DevSecOps scans')]
      )
    }
  }
}
