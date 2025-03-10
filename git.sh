#!/bin/bash

# Load variables from the variables.txt file
source variables.txt

# Get the current folder name
current_folder=$(basename "$PWD")

# Check if all required variables have been set
declare -a variables=("user_name" "user_email" "git_token" "current_folder")

for var in "${variables[@]}"; do
    if [ -z "${!var}" ]; then
        echo "$var is required but not set."
        exit 1
    fi
done

# Check if authenticated to GitHub.com using gh
if ! gh auth status &>/dev/null; then
    echo "Not authenticated to GitHub.com."
    echo "Logging in..."
    # Set the GH_TOKEN environment variable with your personal access token
    export GH_TOKEN="$git_token"
        unset GH_TOKEN

    # Run the gh auth login command without arguments
    gh auth login --hostname "github.com"
fi

# Check if authenticated to GitHub.com using gh
if ! gh auth status &>/dev/null; then
    echo "Unable to authenticate to GitHub.com."
    exit 1
fi

# Check if the repository does not exist
if ! gh repo view username/$current_folder &>/dev/null; then
    echo "Repository does not exist. Creating..."
    
    # Your logic for creating the repository here
    gh repo create "$current_folder" --private
    
    # Rest of your script here
    gh auth logout
else
    echo "Repository already exists."
    exit 1
fi

# Create a .gitignore file if it doesn't exist
if [ ! -f .gitignore ]; then
    touch .gitignore
fi

# Add 'variables.txt' entry to .gitignore if it's not already there
if ! grep -q "variables.txt" .gitignore; then
    echo "variables.txt" >> .gitignore
    echo ".gitignore" >> .gitignore  # Also ignore the .gitignore file itself
fi

# Initialize a new Git repository if not already done
if [ ! -d .git ]; then
    git init

    # Config git setting in current folder to use the correct user name
    git config --local user.name "$user_name"
    git config --local user.email "$user_email"

    # Set the remote URL
    git remote add origin "https://github.com/$user_name/$current_folder.git"

fi

# Add all files to the staging area
git add .

# Commit the code with an initial commit message
current_date=$(date +%Y-%m-%d)
git commit -m 'Auto commit on $current_date'

# Rename the default branch to 'main'
git branch -M main

# Push the code to the remote repository
git push -u origin main

# Check the exit code of git push
if [ $? -eq 0 ]; then

    echo "Git Push successful."
else
    echo "Git Push failed."
fi