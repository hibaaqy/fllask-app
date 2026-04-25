pipeline {
    agent any
    environment {
        //variables defined here can be used by any stage
        NEW_VERSION = '1.3.0'

    }

    stages {
        stage('Build') {
            steps {
                echo 'Building..'
                //using environment variables 
                //to output the value of variable in string use ""
                echo "Building version ${NEW_VERSION}"
            }
        }

        stage('Test') {
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

        success {
            echo 'Pipeline completed successfully.'
        }

        failure {
            echo 'Pipeline failed.'
        }
    }
}
