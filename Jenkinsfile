// DevSecOps pipeline example: scanners run directly via the devsecops-scan CLI inside the
// scanner image; results are stored as JSON + SARIF; the build is gated on the CLI exit code.
//
// Required plugins: Pipeline, Docker Pipeline, Credentials Binding, Timestamper, Warnings Next
// Generation (SARIF publishing), Lockable Resources (serializes DAST on the shared ZAP daemon).
// On Kubernetes, replace the docker agent with the pod template in
// deploy/k8s/jenkins/scanner-pod.yaml (see the comment at the agent block).
//
// Credentials (Jenkins > Manage Credentials, kind "Secret text"):
//   sonar-token    SonarQube analysis token        (only when RUN_SONAR is checked)
//   zap-api-key    API key of the ZAP daemon        (only when DAST_TARGET_URL is set)
//
// CLI exit codes: 0 pass/warn, 1 policy fail, 2 scanner/usage/config error.

pipeline {
  agent {
    docker {
      image(params.SCANNER_IMAGE ?: 'registry.example.com/devsecops-scanner:2.0.0')
    }
    // Kubernetes alternative:
    // kubernetes { yamlFile 'deploy/k8s/jenkins/scanner-pod.yaml'; defaultContainer 'scanner' }
  }

  parameters {
    string(name: 'SCANNER_IMAGE', defaultValue: 'registry.example.com/devsecops-scanner:2.0.0', description: 'Scanner image built with: docker build --target scanner')
    booleanParam(name: 'RUN_SONAR', defaultValue: false, description: 'Also run SonarQube (needs the sonar-token credential)')
    string(name: 'SONAR_HOST_URL', defaultValue: 'http://sonarqube.devsecops.svc:9000', description: 'SonarQube URL reachable from the agent')
    string(name: 'SONAR_PROJECT_KEY', defaultValue: '', description: 'SonarQube project key (defaults to the job name)')
    string(name: 'IMAGE_REF', defaultValue: '', description: 'Container image to scan with Trivy (optional), e.g. registry.example.com/app:1.2.3')
    string(name: 'DAST_TARGET_URL', defaultValue: '', description: 'Staging URL for the ZAP baseline scan (optional; must pass the DAST allowlist)')
    string(name: 'ZAP_URL', defaultValue: 'http://zap.devsecops.svc:8080', description: 'ZAP daemon API URL')
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
        }
        sh 'mkdir -p "$HOME" "$REPORTS_DIR" "$TRIVY_CACHE_DIR"'
      }
    }

    stage('Scans') {
      // --no-fail records results without failing the stage, so every scanner runs and the
      // single gate below decides the build. A scanner error still exits 2 and fails the stage.
      parallel {
        stage('SAST: Semgrep') {
          steps {
            sh 'devsecops-scan sast --tool semgrep --target . --scan-id "sast-semgrep-$SCAN_PREFIX" --no-fail'
          }
        }
        stage('SAST: SonarQube') {
          when { expression { params.RUN_SONAR } }
          steps {
            withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
              withEnv(["SONAR_HOST_URL=${params.SONAR_HOST_URL}", "SONAR_PROJECT_KEY=${params.SONAR_PROJECT_KEY ?: env.JOB_NAME.replaceAll('[^A-Za-z0-9_.:-]', '_')}"]) {
                sh 'devsecops-scan sast --tool sonarqube --project-key "$SONAR_PROJECT_KEY" --target . --scan-id "sast-sonarqube-$SCAN_PREFIX" --no-fail'
              }
            }
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

    stage('DAST: ZAP baseline') {
      when { expression { params.DAST_TARGET_URL?.trim() } }
      options {
        // One ZAP daemon = shared session state; never run two DAST scans on it at once.
        lock(resource: 'zap-daemon')
      }
      steps {
        withCredentials([string(credentialsId: 'zap-api-key', variable: 'ZAP_API_KEY')]) {
          withEnv(["ZAP_URL=${params.ZAP_URL}", "DAST_TARGET_URL=${params.DAST_TARGET_URL.trim()}"]) {
            sh 'devsecops-scan dast --target "$DAST_TARGET_URL" --zap-mode baseline --scan-id "dast-zap-$SCAN_PREFIX" --no-fail'
          }
        }
      }
    }

    stage('Security gate') {
      steps {
        script {
          def ids = ["sast-semgrep-${env.SCAN_PREFIX}", "sca-osv-scanner-${env.SCAN_PREFIX}", "sca-trivy-${env.SCAN_PREFIX}"]
          if (params.RUN_SONAR) { ids << "sast-sonarqube-${env.SCAN_PREFIX}" }
          if (params.IMAGE_REF?.trim()) { ids << "container-trivy-${env.SCAN_PREFIX}" }
          if (params.DAST_TARGET_URL?.trim()) { ids << "dast-zap-${env.SCAN_PREFIX}" }
          def args = ids.collect { "--scan-id ${it}" }.join(' ')

          sh "devsecops-scan report ${args} --format markdown --out security-reports/summary-${env.SCAN_PREFIX}.md"
          // Exit 1 (policy FAIL) or 2 (missing/broken results) fails the build here.
          sh "devsecops-scan gate ${args}"
        }
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'security-reports/**', allowEmptyArchive: true, fingerprint: true
      recordIssues(
        enabledForFailure: true,
        aggregatingResults: false,
        tools: [sarif(pattern: 'security-reports/**/result.sarif', id: 'devsecops', name: 'DevSecOps scans')]
      )
    }
  }
}
