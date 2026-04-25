pipeline {
    agent any

    parameters {
        string(name: 'VERSION', defaultValue: '', description: 'version to deploy')
        
        choice(name: 'VERSION_CHOICE', choices: ['1.1.0', '1.2.0', '1.3.0'], description: 'Select version')

        booleanParam(name: 'executeTests', defaultValue: true, description: 'Run tests or not')
    }

    environment {
        NEW_VERSION = '1.3.0'
    }

    stages {
        stage('Build') {
            steps {
                echo 'Building..'
                echo "Building version ${NEW_VERSION}"
            }
        }

        stage('Test') {
            when {
                expression {
                    return params.executeTests
                }
            }
            steps {
                echo 'Testing..'
            }
        }

        stage('Deploy') {
            steps {
                echo 'Deploying....'
            }
        }
    }

    post {
        always {
            echo 'Pipeline finished.'
        }
    }
}
