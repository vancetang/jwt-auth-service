# PowerShell Script for Initializing Spring Boot Project

# Project details
$groupId = "com.example"
$artifactId = "jwt-auth-service"
$name = "jwt-auth-service"
$description = "JWT Authentication Microservice"
$packageName = "com.example.jwtauthservice"
$javaVersion = "21"
$springBootVersion = "3.3.0"
$dependencies = "web,lombok,security"

# Construct the download URL
$url = "https://start.spring.io/starter.zip?type=maven-project&language=java&bootVersion=$springBootVersion&groupId=$groupId&artifactId=$artifactId&name=$name&description=$([uri]::EscapeDataString($description))&packageName=$packageName&packaging=jar&javaVersion=$javaVersion&dependencies=$dependencies"

# Output file name
$zipFile = "$artifactId.zip"

# Download the project
Write-Host "Downloading Spring Boot project from $url..."
Invoke-WebRequest -Uri $url -OutFile $zipFile
Write-Host "Download complete."

# Extract the project
Write-Host "Extracting $zipFile..."
Expand-Archive -Path $zipFile -DestinationPath . -Force
Write-Host "Extraction complete."

# Remove the downloaded zip file
Write-Host "Removing $zipFile..."
Remove-Item $zipFile
Write-Host "$zipFile removed."

# Change directory to the project folder
Write-Host "Changing directory to $artifactId..."
Set-Location $artifactId

# Build the project
Write-Host "Building the project using Maven Wrapper..."
# Ensure mvnw.cmd is executable (it might not be by default when unzipped)
if (Test-Path -Path "mvnw.cmd") {
    # Attempt to grant execute permissions if possible, though PowerShell's Get-Acl/Set-Acl is complex for simple +x
    # For Windows, .cmd files are generally executable if the filesystem allows execution.
    # The main issue is usually script execution policies for .ps1 files, not .cmd files.
    Write-Host "mvnw.cmd found. Attempting to build..."
    ./mvnw.cmd package
} else {
    Write-Error "mvnw.cmd not found. Please ensure you are in the project root directory and the project was generated correctly."
    Write-Host "Attempting to build with globally installed Maven (mvn package)..."
    mvn package
}

Write-Host "Script execution finished."
Write-Host "If the build was successful, your Spring Boot project '$artifactId' is ready in the '$pwd' directory."
Write-Host "You can now import it into your favorite IDE."
