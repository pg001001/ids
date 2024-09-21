#!/bin/bash

# Check if domain is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

# Function to scan for JavaScript files, download them, and search for sensitive information
scan_information() {
    local domain=$1
    local base_dir="${domain}"
    mkdir -p "${base_dir}"
    mkdir -p "${base_dir}/information/"

    # javaScript files
    echo "Scanning for JavaScript files on ${domain}..."
    
    echo "${domain}" | katana | grep "\.js$" | httpx -mc 200 | tee "${base_dir}/js.txt"
    echo "${domain}" | gau | grep "\.js$" | httpx -mc 200 | tee "${base_dir}/js.txt"

        
    katana ${domain} | grep "\.js$" | httpx -mc 200 | tee -a "${base_dir}/js.txt"
    gau ${domain} | grep "\.js$" | httpx -mc 200 | tee -a "${base_dir}/js.txt"
    
    # cat "${base_dir}/allurls.txt" | grep "\.js$"  "${base_dir}/allurls.txt" | httpx -mc 200 | tee "${base_dir}/js.txt"
    grep "\.js$"  "${base_dir}/allurls.txt" | httpx -mc 200 | tee "${base_dir}/js.txt"

    mkdir -p "${base_dir}/js_files/"  && xargs -a "${base_dir}/js.txt" -I {} wget -q {} -P "${base_dir}/js_files/"

    # sensitive information in downloaded JavaScript files
    echo "Searching for sensitive information in JavaScript files..."
    grep -r --color=always -i -E "aws_access_key|aws_secret_key|api_key" "${base_dir}/js_files/" | tee "${base_dir}/information/sensitive_info.txt"
    # grep -r --color=always -i -E "aws_access_key|aws_secret_key|api key|passwd|pwd|heroku|slack|firebase" "${base_dir}/js_files/" | tee "${base_dir}/information/sensitive_info.txt"
    # grep -r --color=always -i -E "access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key_sid|api.googlemaps AIza|apidocs|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|conn.login|connectionstring|consumer_key|consumer_secret|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|heroku_api_key|sonatype_password|awssecretkey" "${base_dir}/js_files/" >> "${base_dir}//information/sensitive_info.txt"
    
    # endpoints
    grep -r --color=always -i -E "admin|auth|api|jenkins|corp|dev|stag|stg|prod|sandbox|swagger|aws|azure|uat|test|vpn|cms" "${base_dir}/js.txt" >> important_http_urls.txt
    
    # aws s3 files
    grep -r --color=always -i -E "aws|s3" "${base_dir}/js.txt" >> "${base_dir}/information/aws_s3_files.txt"

    # api spicific endpoints
    # katana -mdc "contains(endpoint,"api")" -jc -u ${domain} >> "${base_dir}/information/api_endpoints.txt"
    grep -r --color=always -i -E "api" "${base_dir}/allurls.txt" >> "${base_dir}/information/api_endpoints.txt"
    grep -r --color=always -i -E "apikey|api-key" "${base_dir}/allurls.txt" >> "${base_dir}/information/api_key.txt"

    # mfa urls 
    grep -r --color=always -i -E "oauth_consumer_key|oauth2" "${base_dir}/allurls.txt" >> "${base_dir}/information/mfa_links.txt"

    # tokens urls
    grep -r --color=always -i -E "request_token|token " "${base_dir}/allurls.txt" >> "${base_dir}/information/tokens.txt"

    # pdf and docx files
    grep -r --color=always -i -E "\.pdf" "${base_dir}/allurls.txt" >> "${base_dir}/information/pdfs_file.txt"
    grep -r --color=always -i -E "\.docx|./xlsx" "${base_dir}/allurls.txt" >> "${base_dir}/information/docx_files.txt"

    # emails
    grep -r --color=always -i -E "@" "${base_dir}/allurls.txt" >> "${base_dir}/information/emails.txt"
    grep -r --color=always -i -E "%40" "${base_dir}/allurls.txt" >> "${base_dir}/information/emails.txt"
    grep -r --color=always -i -E "gmail|yahoo|hotmail " "${base_dir}/allurls.txt" >> "${base_dir}/information/common_emails.txt"
    grep -r --color=always -i -E "verify-emails|verify-account" "${base_dir}/allurls.txt" >> "${base_dir}/information/verify-emails.txt"

    # billngs
    grep -r --color=always -i -E "invoice|price|billing|payment" "${base_dir}/allurls.txt" >> "${base_dir}/information/billings.txt"
    grep -r --color=always -i -E "invoice|billing|payment|receipt|pay|bill|purchase|order|checkout|paynow|transaction" "${base_dir}/allurls.txt" >> "${base_dir}/information/pay.txt"

    
    # orders related urls
    grep -r --color=always -i -E "confirm|order-detail" "${base_dir}/allurls.txt" >> "${base_dir}/information/confirm.txt"
    grep -r --color=always -i -E "return" "${base_dir}/allurls.txt" >> "${base_dir}/information/return.txt"
    grep -r --color=always -i -E "track|trk" "${base_dir}/allurls.txt" >> "${base_dir}/information/track.txt"
    
    # account related urls
    grep -r --color=always -i -E "account|your-account" "${base_dir}/allurls.txt" >> "${base_dir}/information/accounts.txt"

    # links related urls - urls which redirect to different urls showcasing information 
    grep -r --color=always -i -E "link|crm" "${base_dir}/allurls.txt" >> "${base_dir}/information/links.txt"

    # credentials
    grep -r --color=always -i -E "register|signin|signup|forgotpassword|forgot-password|login|profile" "${base_dir}/allurls.txt" >> "${base_dir}/information/credentials.txt"

    # personal informations url
    grep -r --color=always -i -E "firstName|lastName|address|phone|resume" "${base_dir}/allurls.txt" >> "${base_dir}/information/personal_information.txt"

    #search sensitive files 
    # waybackurls "${domain}" | grep - -color -E "1.xls | \\. xml | \\.xlsx | \\.json | \\. pdf | \\.sql | \\. doc| \\.docx | \\. pptx| \\.txt| \\.zip| \\.tar.gz| \\.tgz| \\.bak| \\.7z| \\.rar" >> "${base_dir}/information/file.txt"
    grep -r --color=always -i -E "\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.zip|\.tar.gz|\.tgz|\.bak|\.7z|\.rar" "${base_dir}/allurls.txt" >>  "${base_dir}/information/sensitive_files.txt"

    # rm -r "${base_dir}/js_files/"

}

# Run the JS scan function with the provided domain
scan_information "$1"
