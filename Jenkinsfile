pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                echo 'Building..'
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
        //the condition here will execue after the build is done
    always {
            //this action will happen always regardlessof the result of build
             echo 'Post Build condition running'
            }
    failure {
            //this action will happen only if the build has failed
             echo 'Post Action if Build Failed
            }
    }
}
