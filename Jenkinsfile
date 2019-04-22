properties([
  gitLabConnection('gitlab'),
  [$class: 'BuildDiscarderProperty', strategy: [$class: 'LogRotator', numToKeepStr: '100']]
])

def version = ""
def golang_image = 'golang:1.12-alpine3.8'
def gcs_store = 'gs://boxops/dockcmd/releases'
def releaseBranch = 'master'
def currentBranch = env.BRANCH_NAME
def release = false

throttle(['docker']) {
  node('docker') {

    try {
      stage('Setup') {
        checkout scm
        updateGitlabCommitStatus(name: 'jenkins-build', state: 'running')
        def tag = gitTagName()

        if (releaseBranch == currentBranch && tag != null) {
          version = "VERSION=${tag}"
          release = true
        }
      }

      stage('Build') {
        sh """
          docker container run -t -v "${env.WORKSPACE}:/dockcmd" ${golang_image} \
          sh -c "apk --no-cache add git make tar gzip && \
          cd /dockcmd && \
          make test && \
          ${version} make release"
        """
      }

      stage ('Release') {
        if (release) {
          googleStorageUpload(
            bucket: gcs_store,
            credentialsId: 'boxboat-prod-gcp',
            pathPrefix: 'release/',
            pattern: 'release/**/*.tgz',
            sharedPublicly: true)
        }
      }


      updateGitlabCommitStatus(name: 'jenkins-build', state: 'success')
    } catch (Exception e) {
      updateGitlabCommitStatus(name: 'jenkins-build', state: 'failed')
      throw e
    }
  }
}

/** @return The tag name, or `null` if the current commit isn't a tag. */
String gitTagName() {
  commit = sh(script: 'git rev-parse HEAD', returnStdout: true)?.trim()
  if (commit) {
    desc = sh(
      script: """
        set -e
        git describe --tags ${commit}
        set +e
      """ ,
      returnStdout: true)?.trim()

    // ensure it is a tag
    match = desc =~ /.+-[0-9]+-g[0-9A-Fa-f]{6,}$/
    result = !match
    match = null // prevent serialisation

    if (result) {
      return desc
    }
  }
  return null
}
