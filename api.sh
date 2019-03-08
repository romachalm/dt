#!/bin/bash
TSMURL="https://[gitlab]/api/v3/projects"
TOKEN="[token]"

# Retrieve base64 content of a file for a given repository
function get_content {
  filepath=$2
  repository_id=$1  
  # echo $(curl -s --request GET --header "PRIVATE-TOKEN: $TOKEN" "$TSMURL/$repository_id/repository/files?file_path=$filepath&ref=master")
  echo $(curl -s --request GET --header "PRIVATE-TOKEN: $TOKEN" "$TSMURL/$repository_id/repository/files?file_path=$filepath&ref=master" | jq .content)
}
# Decode content and write in a local file 
function read_file {
  repository_id=$1
  filepath=$2
  target=$3
  echo $(get_content $repository_id $filepath) | base64 -di > $target
}
# Exceute update of the file. It must exist on the repository. 
# Any commit is recorded even though there is no modification in the file
function exec_commit {
  URL="$TSMURL/$1/repository/commits"
  file=$( basename $2 )
  content=$3
  commit_msg="$4"
  PAYLOAD=$(cat << EOF
{
  "branch_name": "master",
  "commit_message": "$commit_msg",
  "actions": [
    {
      "action": "update",
      "file_path": "$file",
      "content": "$content",
      "encoding": "base64"
    }
  ]
}
EOF
)
  curl --request POST --header "PRIVATE-TOKEN: $TOKEN" --header "Content-Type: application/json" $URL --data "$PAYLOAD"
}
# Check the content of remote branch and local file, if diff, commit the difference
function commit_file {
  repository_id="$1"
  file="$2"
  commit_msg="$3"
  encoded="$(cat $file | base64 --wrap 0)"
  distant="$(echo $(get_content $repository_id $file) )"
  #echo "encoded : \"$encoded\""
  #echo "distant : $distant"
  if [[ ! "\"$encoded\"" == "$distant" ]]
  then
    echo "Modified file, commit"
    exec_commit "$repository_id" "$file" "$encoded" "$commit_msg"
  else
    echo "Unchanged file, skip"
  fi
}
# Get a file from tsm
#read_file 99 "url.csv" "urls.txt"
#commit a file to tsm
#commit_file 103 test.csv "test via API Laurent"