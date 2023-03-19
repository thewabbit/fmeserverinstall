$logFile = $MyInvocation.MyCommand.Name+".log"

#Installer Details
$installer = ".\fme-server-2022.1.1-b22623-win-x64.exe"
$sqlODBC = ".\msodbcsql.msi"
$sqlCMD = ".\MsSqlCmdLnUtils.msi"

#FMEExtract Parameters
$tempExtractPath = "C:\temp\fmeserverinstall"
$extractFlags = "EXTRACTONLY"

#FMEInstall Parameters
$extractedFolder = $tempExtractPath
$installLocation = "D:\Application\FMEServer"
$sharedResources = "G:\applicationdata\FMEServer"
$logs = "L:\application\FMEServer"
$servletPort = "8080"
$dbHost = ""
$dbPort = "50200"
$dbUser = ""
$dbPassword = ""
$dbName = ""
$jdbcString = "jdbc:sqlserver://{0};port={1};databaseName={2}" -f $dbHost,$dbPort,$dbName
$FMEServerURL = ""
$HTTPS = "443"


#FME PostInstall Parameters
$adminPassword = "fmeserverpassword"
$admin2UserName = "admin2"
$admin2Password = "fmeserverpassword"

#FME Windows SVC account
$SVCUsername = ""
$SVCPassword  = ""

#Certificate Parameters
$pfxLoc = ""
$pfxPassword = ""

#SMTP Parameters
$smtpServer = ""
$smtpPort = "25"
$smtpAccount = ""
$smtpPassword = ""
$smtpEmail = ""
$smtpSecurity = "NONE" #NONE|SSL/TLS|STARTTLS
$monitorEmail = ""


Function Log
{
    Param ([string]$logString)
    $timeStamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $logMessage = "$timeStamp $logString"

    Add-content $logFile -value $logMessage
    Write-Output $logMessage
}


##########Extract Installer##########
function extract
{
# check an extracted install doesn't already exist
Remove-Item $tempExtractPath  -Recurse -Force

Log "Extracting $installer"
Log "Extracting FME Server Install to $tempExtractPath"

Start-Process -FilePath $installer -ArgumentList "-d$tempExtractPath -s -sp$extractFlags" -Wait
Log "Extracted FME Server successfully to $tempExtractPath"
}


##########Install FME##########
function install
{
    # Create application folder
    Log "Creating path: $installLocation"
    New-Item -ItemType Directory -Force -Path $installLocation
    # Create shared resource dir
    Log "Creating path: $sharedResources"
    New-Item -ItemType Directory -Force -Path $sharedResources

    $setup = Join-Path $extractedFolder "fme-server.msi"
    $installArgs = @(
        # "FIRSTLOGINCHANGEPASSWORD=$firstLoginChange"
        "ADDLOCAL=FMEServerCore,FMEEngine,Services"
        "/norestart"
        "/l*v installFMEServerLog.txt"
        "/qb"
        "INSTALLDIR=$installLocation"
        "FMESERVERUSER=$SVCUsername"
        "FMESERVERUSERPASSWORD=$SVCPassword"
        "FMESERVERSHAREDDATA=$sharedResources"
        "SERVLETPORT=$servletPort"
        "DATABASETYPE=MSSQL" 
        "DATABASECONNECTIONSTRING=$jdbcString"
        "DATABASEUSER=$dbUser"
        "DATABASEPASSWORD=$dbPassword"
    )

    Log "Installing FME Server to $installLocation"
    Log "$installArgs"
    Start-Process -FilePath $setup -ArgumentList $installArgs -wait

    Start-Sleep -Seconds 30

    Stop-Service -Name FME*

    Log "FME Server Install completed."
}


##########Post Install##########
function postInstall
{
    Log "Starting post install"

    Log "Stopping FME Services"
    Stop-Service -Name FME*
    Start-Sleep -Seconds 30



    ##########Install SQL components##########
    $sqlInstalls = "msoledbsql.msi", "SQLSysClrTypes.msi"
    foreach ($s in $sqlInstalls)
    {
        $setup = Join-Path $extractedFolder $s
        Log "Installing $s"
        Start-Process -FilePath $setup -ArgumentList "/qb" -wait

        Start-Sleep -Seconds 5

        Log "Installed $s"
    }

    Start-Process -FilePath $sqlODBC -ArgumentList "/qb" -wait
    Start-Process -FilePath $sqlCMD -ArgumentList "/qb" -wait





    ##########Run SQL setup scripts##########
    $createSchema = Join-Path $installLocation "\Server\database\sqlserver\sqlserver_createDB.sql"

    #fix user sql script
    ((Get-Content -path $createSchema -Raw) -replace "CREATE DATABASE fmeserver;","") | Set-Content -Path $createSchema
    ((Get-Content -path $createSchema -Raw) -replace "USE fmeserver;","USE $dbName;") | Set-Content -Path $createSchema


    sqlcmd -S $dbHost,$dbPort -d $dbName -U $dbUser -P $dbPassword -i $createSchema

    Log "Starting FME Services"
    Start-Service -Name FME*
    Start-Sleep -Seconds 60
    



    ##########Change admin passwords##########
    Log 'Changing Admin password'
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $auth = 'admin:admin'
    $Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
    $authorizationInfo = [System.Convert]::ToBase64String($Encoded)
    
    $headers.Add("Authorization", "Basic $authorizationInfo")
    $headers.Add("Content-Type", "application/x-www-form-urlencoded")
    $body = "currentPassword=admin&newPassword=$adminPassword"
    
    
    $response = Invoke-WebRequest -Uri "http://localhost:$servletPort/fmerest/v3/security/accounts/admin/password/reset" -Method PUT -Headers $headers -Body $body
    if ($response.StatusCode -ine 204){
       Log 'Failed to change admin password'
       throw 'Error updating password'
    }
    Log 'Successfully changed admin password'
    
    #set auth with new password
    $auth = "admin:$adminPassword"
    $Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
    $authorizationInfo = [System.Convert]::ToBase64String($Encoded)
    
    
    #make secondary admin user
    Log 'Creating second admin account'
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Basic $authorizationInfo")
    $headers.Add("Content-Type", "application/x-www-form-urlencoded")
    $body = "fullName=Administrator2&enabled=true&name=$admin2UserName&password=$admin2Password&passwordChangeNeeded=false&roles=fmesuperuser&roles=fmeadmin&sharingEnabled=true"
    
    $response = Invoke-WebRequest -Uri "http://localhost:$servletPort/fmerest/v3/security/accounts" -Method "POST" -Headers $headers -Body $body
    if ($response.StatusCode -ine 201){
       throw 'Error creating secondary admin accout'
    }
    Log 'Successfully created second admin user'


    ##########Log Locations##########
    $fmeEngineConfig = Join-Path $installLocation "\Server\fmeEngineConfig.txt"
    $fmeServerConfig = Join-Path $installLocation "\Server\fmeServerConfig.txt"
    $engineMessageLoggerProperties = Join-Path $installLocation "\Server\config\logger\engine\messagelogger.properties"
    $coreMessageLoggerProperties = Join-Path $installLocation "\Server\config\logger\core\messagelogger.properties"
    $tomcatLoggingProperties = Join-Path $installLocation "\Utilities\tomcat\conf\logging.properties"
    $tomcatServer= Join-Path $installLocation "\Utilities\tomcat\conf\server.xml"
    $tomcatWEBINF = Join-Path $installLocation "\Utilities\tomcat\webapps\fmerest\WEB-INF\conf\propertiesFile.properties"
    $messageLogger = Join-Path $installLocation "\Utilities\config\messagelogger.properties"
    $redisConf = Join-Path $installLocation "\Utilities\redis\redis.conf"


    # Create log folder
    Log "Creating path: $logs"
    New-Item -ItemType Directory -Force -Path $logs
    $logString = $logs.Replace("\","/")
    $sharedResourcesFixed = $sharedResources.Replace("\","/")

    # repoint logs
    Log "Repointing Logs"
    Log "Updating $fmeEngineConfig"
    Log "FME_TRANSFORMATION_LOG_DIR ""$logString/engine/current/jobs"""
    ((Get-Content -path $fmeEngineConfig -Raw) -replace "FME_TRANSFORMATION_LOG_DIR ""!FME_SERVER_ROOT!/resources/logs/engine/current/jobs""","FME_TRANSFORMATION_LOG_DIR ""$logString/engine/current/jobs""") | Set-Content -Path $fmeEngineConfig
    ((Get-Content -path $fmeEngineConfig -Raw) -replace "MACRO_DEF FME_SHAREDRESOURCE_LOG ""$sharedResourcesFixed/resources/logs/""","MACRO_DEF FME_SHAREDRESOURCE_LOG ""$logString/logs/""") | Set-Content -Path $fmeEngineConfig
    Log "Updated $fmeEngineConfig"

    Log "Updating $fmeServerConfig"
    ((Get-Content -path $fmeServerConfig -Raw) -replace "SHAREDRESOURCE_DIR_1=$sharedResourcesFixed/resources/logs/","SHAREDRESOURCE_DIR_1=$logString") | Set-Content -Path $fmeServerConfig
    ((Get-Content -path $fmeServerConfig -Raw) -replace "LOGS_HOME=$sharedResourcesFixed/resources/logs","LOGS_HOME=$logString") | Set-Content -Path $fmeServerConfig
    Log "Updated $fmeServerConfig"

    Log "Updating $engineMessageLoggerProperties"
    ((Get-Content -path $engineMessageLoggerProperties -Raw) -replace "LOG_FILE_PATH = $sharedResourcesFixed/resources/logs/engine","LOG_FILE_PATH = $logString/engine") | Set-Content -Path $engineMessageLoggerProperties
    Log "Updated $engineMessageLoggerProperties"

    Log "Updating $coreMessageLoggerProperties"
    ((Get-Content -path $coreMessageLoggerProperties -Raw) -replace "LOG_FILE_PATH = $sharedResourcesFixed/resources/logs/core","LOG_FILE_PATH = $logString/core") | Set-Content -Path $coreMessageLoggerProperties
    Log "Updated $coreMessageLoggerProperties"

    Log "Updating $messageLogger"
    ((Get-Content -path $messageLogger -Raw) -replace "LOG_FILE_PATH = $sharedResourcesFixed/resources/logs/service","LOG_FILE_PATH = $logString/service") | Set-Content -Path $messageLogger
    Log "Updated $messageLogger"

    Log "Updating $tomcatLoggingProperties"
    ((Get-Content -path $tomcatLoggingProperties -Raw) -replace "$sharedResourcesFixed/resources/logs","$logString") | Set-Content -Path $tomcatLoggingProperties
    Log "Updated $tomcatLoggingProperties"

    Log "Updating $tomcatServer"
    ((Get-Content -path $tomcatServer -Raw) -replace "$sharedResourcesFixed/resources/logs","$logString") | Set-Content -Path $tomcatServer
    Log "Updated $tomcatServer"

    Log "Updating $tomcatWEBINF"
    ((Get-Content -path $tomcatWEBINF -Raw) -replace "$sharedResourcesFixed/resources/logs","$logString") | Set-Content -Path $tomcatWEBINF
    Log "Updated $tomcatWEBINF"

    Log "Updating $redisConf"
    ((Get-Content -path $redisConf -Raw) -replace "$sharedResourcesFixed/resources/logs","$logString") | Set-Content -Path $redisConf
    Log "Updated $redisConf"

    Log "Logs updated"


    ##########update services##########
    $services = @("fmedatadownload","fmedatastreaming","fmedataupload","fmejobsubmitter","fmekmllink","fmenotification")

    foreach ($s in $services){
        Log "Updating $s"
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Authorization", "Basic $authorizationInfo")
        $headers.Add("Content-Type", "application/x-www-form-urlencoded")
        $body = "url=https://{0}/{1}" -f $FMEServerURL,$s
        $uri =  "http://localhost:{0}/fmerest/v3/services/{1}"-f $servletPort,$s

        $response = Invoke-WebRequest -Uri $uri -Method "PUT" -Headers $headers -Body $body
        if ($response.StatusCode -ine 204){
            Log "Error updating $s"
        } else {
            Log "Successfully updated $s"
        }

    }



    ##########Set Email details##########
    Log 'Setting system email settings'
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Basic $authorizationInfo")
    $headers.Add("Content-Type", "application/x-www-form-urlencoded")
    $body = "SMTP_SERVER=$smtpServer&SMTP_SERVER_PORT=$smtpPort&SMTP_SERVER_ACCOUNT=$smtpAccount&SMTP_SERVER_PASSWORD=$smtpPassword&SMTP_SERVER_SECURITY=$smtpSecurity&EMAIL_FROM=$smtpEmail"

    $response = Invoke-WebRequest -Uri "http://localhost:$servletPort/fmerest/v3/configuration/systememail" -Method "PUT" -Headers $headers -Body $body
    if ($response.StatusCode -ine 204){
        throw 'Error updating smtp details'
    } else {
        Log 'Successfully updated system email settings'
    }

    #update subscription emails

    #get all subscriptions that are emails
    Log 'Getting subscriptions'
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Basic $authorizationInfo")


    $response = Invoke-WebRequest -Uri "http://localhost:$servletPort/fmerest/v3/notifications/subscriptions" -Method "GET" -Headers $headers
    if ($response.StatusCode -ine 200){
        throw 'Error updating smtp details'
    } else {
        Log 'Successfully updated system email settings'
    }


    $json = $response.Content | ConvertFrom-Json

    foreach ($item in $json.items)
    {
        if ($item.subscriberName -eq "email")
        {
            #iterate through and update stmp details for each connection
            $name = $item.name
            Log "Updating $name"
            $item.properties[12].value = $smtpServer
            $item.properties[2].value = $smtpPort
            $item.properties[1].value = $smtpAccount
            $item.properties[7].value = $smtpPassword
            $item.properties[3].value = $smtpEmail
            $item.properties[0].value = $monitorEmail

            $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $headers.Add("Authorization", "Basic $authorizationInfo")
            $headers.Add("Content-Type", "application/json")

            $body = $item | ConvertTo-Json

            $response = Invoke-WebRequest -Uri "http://localhost:$servletPort/fmerest/v3/notifications/subscriptions/$name" -Method "PUT" -Headers $headers -Body $body
            if ($response.StatusCode -ine 204){
                $response.StatusCode
                throw 'Error updating smtp details'
            } else {
                Log "Updated $name"
            }
        }
    }

    #create topic for emails
    Log 'Adding generic email topic'
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Basic $authorizationInfo")
    $headers.Add("Content-Type", "application/x-www-form-urlencoded")

    $body = $item | ConvertTo-Json

    $response = Invoke-WebRequest -Uri "http://localhost:$servletPort/fmerest/v3/notifications/topics" -Method "POST" -Headers $headers -Body "description=Send basic email&name=send_email"
    if ($response.StatusCode -ine 201){
        $response.StatusCode
        throw 'Error updating creating topic'
    } else {
        Log 'Added generic email topic'
    }
    
    #create new subscription
    Log 'Adding generic email subscription'
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Basic $authorizationInfo")
    $headers.Add("Content-Type", "application/json")

    $body = @"
    {
        "topics":["send_email"],
        "name":"send_email",
        "properties":[
            {"name":"SMTP_SERVER","value":"$smtpServer"},
            {"name":"SMTP_SERVER_PORT","value":$smtpPort},
            {"name":"SMTP_SERVER_ACCOUNT","value":"$smtpAccount"},
            {"name":"SMTP_SERVER_PASSWORD","value":"$smtpPassword"},
            {"name":"SMTP_SERVER_SECURITY","value":"SSL/TLS"},
            {"name":"EMAIL_TO","value":"$monitorEmail"},
            {"name":"EMAIL_CC","value":""},
            {"name":"EMAIL_BCC","value":""},
            {"name":"EMAIL_FROM","value":"$smtpEmail"},
            {"name":"EMAIL_SUBJECT","value":""},
            {"name":"EMAIL_CONTENT_TYPE","value":"HTML"},
            {"name":"EMAIL_ATTACHMENT","value":""},
            {"name":"EMAIL_TEMPLATE","value":""}
            ],
        "subscriberName":"email"
    }
"@

    $response = Invoke-WebRequest -Uri "http://localhost:$servletPort/fmerest/v3/notifications/subscriptions" -Method "POST" -Headers $headers -Body $body
    if ($response.StatusCode -ine 201){
        $response.StatusCode
        throw 'Error adding generic email subscription'
    } else {
        Log 'Added generic email subscription'
    }



    ##########set https##########
    Log 'Setting https'
    $serverXML = Join-Path $installLocation "\Utilities\tomcat\conf\server.xml"
    $webXML = Join-Path $installLocation "\Utilities\tomcat\conf\web.xml"
    $contextXML = Join-Path $installLocation "\Utilities\tomcat\conf\context.xml"
    $fmeServerConfig = Join-Path $installLocation "Server\fmeServerConfig.txt"

    Log "Updating $fmeServerConfig"
    $replaceString = "FME_SERVER_WEB_URL=http://{0}:{1}" -f $FMEServerURL,$servletPort
    $newString = "FME_SERVER_WEB_URL=https://{0}" -f $FMEServerURL
    ((Get-Content -path $fmeServerConfig -Raw) -replace $replaceString,$newString) | Set-Content -Path $fmeServerConfig


    Log "Updating $serverXML"
    #update server xml
    ((Get-Content -path $serverXML -Raw) -replace 'SSLEngine="on"','SSLEngine="off"') | Set-Content -Path $serverXML

    $pfxSource = $pfxLoc
    $pfxName = Split-Path $pfxLoc -leaf
    $pfxDestFolder = Join-Path $installLocation "\Utilities\tomcat\"

    Copy-Item $pfxSource -Destination $pfxDestFolder

    $content = Get-Content -path $serverXML -Raw
    $content -match '<Connector port="{0}"[^>]*>' -f $servletPort
    $httpsConfigServer = @"
    <Connector protocol="org.apache.coyote.http11.Http11NioProtocol" port="$HTTPS" minSpareThreads="5" enableLookups="true" disableUploadTimeout="true"
    acceptCount="100" maxThreads="200"
    scheme="https" secure="true" SSLEnabled="true"
    keystoreFile="$(Join-Path $pfxDestFolder $pfxName)"
    keystorePass="$pfxPassword"
    keystoreType="PKCS12"
    clientAuth="false" sslEnabledProtocols="TLSv1,TLSv1.1,TLSv1.2"
    sslImplementationName="org.apache.tomcat.util.net.jsse.JSSEImplementation"
    ciphers="TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA,SSL_RSA_WITH_3DES_EDE_CBC_SHA" URIEncoding="UTF8" />
    <Connector port="80" protocol="HTTP/1.1" redirectPort="$HTTPS"/>
"@

    ((Get-Content -path $serverXML -Raw) -replace $matches[0],"<!-- $($matches[0]) -->`n$httpsConfigServer") | Set-Content -Path $serverXML
    Log "Updated $serverXML"

    #update web xml
    $httpsConfigWeb = @"
    <security-constraint>
    <web-resource-collection>
    <web-resource-name>HTTPSOnly</web-resource-name>
    <url-pattern>/*</url-pattern>
    </web-resource-collection>
    <user-data-constraint>
    <transport-guarantee>CONFIDENTIAL</transport-guarantee>
    </user-data-constraint>
    </security-constraint>
"@

    Log "Updating $webXML"
    ((Get-Content -path $webXML -Raw) -replace "</web-app>","$httpsConfigWeb`n</web-app>") | Set-Content -Path $webXML
    Log "Updated $webXML"

    #update context xml
    $httpsConfigContext = '<Valve className="org.apache.catalina.authenticator.SSLAuthenticator" disableProxyCaching="false" />'

    Log "Updating $contextXML"
    ((Get-Content -path $contextXML -Raw) -replace "</Context>","$httpsConfigContext`n</Context>") | Set-Content -Path $contextXML
    Log "Updated $contextXML"

    Start-Sleep -Seconds 120

    #restart all FME services
    Restart-Service -Name FME* -Force
}






##########Run##########

extract
install
postInstall