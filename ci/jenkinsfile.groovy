// ZeroCyber v7 — Jenkins Pipeline Snippet
// Add this to your Jenkinsfile

pipeline {
    agent any

    environment {
        ZEROCYBER_VERSION = '7.0.0'
        ZEROCYBER_FORMAT = 'sarif'
        ZEROCYBER_OUTPUT = 'zerocyber-report.sarif'
    }

    stages {
        stage('Install ZeroCyber') {
            steps {
                sh '''
                    python3 -m pip install --user tree-sitter tree-sitter-python tree-sitter-javascript tree-sitter-typescript tree-sitter-go jinja2
                    # Install from PyPI or local
                    python3 -m pip install --user zerocyber || echo "Install from local"
                '''
            }
        }

        stage('ZeroCyber Security Scan') {
            steps {
                sh '''
                    python3 -m zerocyber_v7.cli scan . \
                        --format ${ZEROCYBER_FORMAT} \
                        --output ${ZEROCYBER_OUTPUT} \
                        --workers 4 \
                        --verbose
                '''
            }
        }

        stage('Generate HTML Report') {
            steps {
                sh '''
                    python3 -m zerocyber_v7.cli scan . \
                        --format html \
                        --output zerocyber-report.html \
                        --workers 4
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'zerocyber-report.*', allowEmptyArchive: true
            publishHTML(target: [
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: '.',
                reportFiles: 'zerocyber-report.html',
                reportName: 'ZeroCyber Security Report'
            ])
        }
    }
}
