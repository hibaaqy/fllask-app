pipeline {
    agent any
        parameter {
                  //these are types of parameters
                  string(name: 'VERSION',defaultValue:'',description:'version to deploy on prod')
                  choice (name: 'VERSION',CHOICES:['1.1.0', 1.2.0', 1.3.0'], DESCRIPTION:'']
                  booleanParam(name:'executeTests',defaultValue: true, description:'')
            
            } 
            
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
                sh "nvm install"
            }
        }

        stage('Test') {
               when {
                    expression {
                             params.executeTests
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

        success {
            echo 'Pipeline completed successfully.'
        }

        failure {
            echo 'Pipeline failed.'
        }
    }
}
