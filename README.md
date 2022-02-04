[comment]: # "Auto-generated SOAR connector documentation"
# ThreatConnect

Publisher: Splunk  
Connector Version: 2\.2\.5  
Product Vendor: ThreatConnect  
Product Name: ThreatConnect  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.1\.0  

This app integrates with the ThreatConnect platform to provide various hunting actions in addition to threat ingestion

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a ThreatConnect asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**access\_id** |  required  | string | Access ID
**base\_url** |  required  | string | Base URL for instance \(e\.g\. https\://api\.threatconnect\.com\)
**secret\_key** |  required  | password | Secret Key
**max\_containers** |  optional  | numeric | Max containers per poll
**interval\_days** |  optional  | numeric | Last 'N' Days to get data during 'Poll Now' and scheduled polling
**verify\_server\_cert** |  optional  | boolean | Verify server cert

### Supported Actions  
[on poll](#action-on-poll) - Callback action for the on\_poll ingest functionality  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[list owners](#action-list-owners) - List the owners visible with the configured credentials  
[post data](#action-post-data) - Create an indicator and post it to ThreatConnect  
[hunt ip](#action-hunt-ip) - Hunt an IP and retrieve any available information  
[hunt file](#action-hunt-file) - Hunt a file hash and retrieve available information  
[hunt email](#action-hunt-email) - Hunt an email and retrieve available information  
[hunt domain](#action-hunt-domain) - Hunt a domain and retrieve available information  
[hunt url](#action-hunt-url) - Hunt a URL and retrieve available information  

## action: 'on poll'
Callback action for the on\_poll ingest functionality

Type: **ingest**  
Read only: **True**

<p>Basic polling configuration is available within the asset configuration\.  <b>On\_poll</b>'s maximum ingested indicators is, by default, 100\.  This can be found in the asset configuration under <b>max\_containers</b>\.  The other optional parameter in the asset configuration, <b>num\_of\_days</b>, specifies how old to start polling from during the first ingestion cycle\.  The default value is 7 days\.  This <b>num\_of\_days</b> parameter also affects when the Poll Now starts polling as well\.</p><p>This action will start from the oldest indicator and create a container for each\.</p><p>The following CEF fields will be created, depending upon the IOC type\:</p><table><tr><th>IOC</th><th>Artifact Name</th><th>CEF Field</th></tr><tr><td>Address IPv4</td><td>IP Artifact</td><td>deviceAddress</td></tr><tr><td>Address IPv6</td><td>IP Artifact</td><td>deviceCustomIPv6Address1</td></tr><tr><td>Email</td><td>Email Address Artifact</td><td>emailAddress</td></tr><tr><td>File</td><td>File Artifact</td><td>fileHashMd5, fileHashSha1, fileHashSha256 \(where applicable\)</td></tr><tr><td>Host</td><td>Domain Artifact</td><td>DeviceDnsDomain</td></tr><tr><td>URL</td><td>URL Artifact</td><td>requestURL</td></tr><tr><td>CIDR IPv4</td><td>CIDR Artifact</td><td>deviceAddress \(IP\), cidrPrefix, cidr \(CIDR\)</td></tr><tr><td>Mutex</td><td>Mutex Artifact</td><td>mutex</td></tr><tr><td>Registry Key</td><td>Registry Key Artifact</td><td>registryKey \(Registry Key Name\), registryValue \(Value Name\), registryType \(Value Type\)</td></tr><tr><td>ASN</td><td>ASN Artifact</td><td>asn</td></tr><tr><td>User Agent</td><td>User Agent Artifact</td><td>requestClientApplication</td></tr></table><p>Additional CEF fields that all artifacts will have are\:</p><table><tr><th>CEF Field</th><th>Description</th></tr><tr><td>deviceCustomDate1</td><td>Date Created</td></tr><tr><td>deviceCustomDate1Label</td><td>Label for above</td></tr><tr><td>deviceCustomDate2</td><td>Last Modified Date</td></tr><tr><td>deviceCustomDate2Label</td><td>Label for above</td></tr><tr><td>rating</td><td>Indicator rating</td></tr><tr><td>confidence</td><td>Indicator confidence</td></tr><tr><td>threatAssessRating</td><td>Threat Assessment rating</td></tr><tr><td>threatAssessConfidence</td><td>Threat Assessment Confidence</td></tr></table><p>Rating, confidence, threatAssessRating, and threatAssessConfidence will only be added if they are present within the indicator\.</p><p>Any indicator that does not fall within any of the categories above is considered a custom indicator, and, as a result, will have a CEF field of 'cn1'\.</p><p>It is also very important that the Maximum Container for scheduled polling configured should be greater than the maximum events that are generated per second\. If the app detects it got the maximum configured events and all occurred in the same second, it will start polling from the next second in the next polling cycle\.</p>

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

This action attempts to authenticate a GET request with the ThreatConnect API using a signature\.

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'list owners'
List the owners visible with the configured credentials

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.data\.owner\.\*\.id | numeric | 
action\_result\.data\.\*\.data\.owner\.\*\.name | string | 
action\_result\.data\.\*\.data\.owner\.\*\.type | string | 
action\_result\.data\.\*\.data\.resultCount | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.summary\.num\_owners | numeric | 
action\_result\.summary\.total\_objects | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'post data'
Create an indicator and post it to ThreatConnect

Type: **generic**  
Read only: **False**

<p>This action will post an indicator back to the ThreatConnect platform\. The only required field is <b>primary\_field</b>\. This parameter can be an IP address, an email, a hash \(MD5, SHA\-1, or SHA\-256\), a hostname, or a URL\.</p><p>This action also allows for one to post multiple hashes into one indicator\. To post multiple hashes to one indicator, put all the hashes in the <b>primary\_field</b> separated by commas\. An indicator can have a maximum of one MD5, one SHA\-1, and one SHA\-256 hash\. If multiple hashes of the same type are entered into the primary field, such as multiple MD5 hashes, the last hash will be the only one posted\.</p><p>All indicator types can take the optional parameters <b>rating</b> and <b>confidence</b>\. The specialized optional parameters for files and hosts are below\:</p>Files<ul><li>size</li></ul>Hosts<ul><li>dns\_active</li><li>whois\_active</li></ul><p>This action also allows for the addition of attributes to the specified indicator that is created\. The attribute will only be created if both the <b>attribute\_name</b> and the <b>attribute\_value</b> values are populated\. If attempting to write an attribute with a name that does not exist or apply to the indicator's type, the action will fail\.</p><p>The data paths listed below are all the <i>possible</i> data paths, but they will differ based upon the given parameter in <b>primary\_field</b>\. The data paths will be of the form of <b>action\_result\.data\.\*\.\[Indicator Type\]\.\*</b>, where the Indicator Type is the type given to the parameter in <b>primary\_field</b>\. All file hashes will have the same Indicator Type\. If one attempts to post an indicator that already exists on ThreatConnect, that indicator will be updated\.</p>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**confidence** |  optional  | Analytic confidence \(0 to 100\) | numeric | 
**dns\_active** |  optional  | Is DNS active | boolean | 
**primary\_field** |  required  | IP, email, file hash, domain, or URL | string |  `ip`  `ipv6`  `email`  `hash`  `md5`  `sha1`  `sha256`  `domain`  `url` 
**rating** |  optional  | Indicator rating \(0 to 5\) | numeric | 
**size** |  optional  | Size of file in bytes | numeric | 
**whois\_active** |  optional  | Is WHOIS active | boolean | 
**attribute\_name** |  optional  | Name of attribute to add | string | 
**attribute\_value** |  optional  | Value of attribute to add | string | 
**tag** |  optional  | Name of Indicator Tag to add | string | 
**security\_label** |  optional  | Name of Security Label to add | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.attribute\_name | string | 
action\_result\.parameter\.attribute\_value | string | 
action\_result\.parameter\.confidence | string | 
action\_result\.parameter\.dns\_active | boolean | 
action\_result\.parameter\.primary\_field | string |  `ip`  `ipv6`  `email`  `hash`  `md5`  `sha1`  `sha256`  `domain`  `url` 
action\_result\.parameter\.rating | string | 
action\_result\.parameter\.size | string | 
action\_result\.parameter\.tag | string | 
action\_result\.parameter\.security\_label | string | 
action\_result\.parameter\.whois\_active | boolean | 
action\_result\.data\.\*\.data\.address\.confidence | numeric | 
action\_result\.data\.\*\.data\.address\.dateAdded | string | 
action\_result\.data\.\*\.data\.address\.description | string | 
action\_result\.data\.\*\.data\.address\.id | numeric | 
action\_result\.data\.\*\.data\.address\.ip | string |  `ip` 
action\_result\.data\.\*\.data\.address\.lastModified | string | 
action\_result\.data\.\*\.data\.address\.owner\.id | numeric | 
action\_result\.data\.\*\.data\.address\.owner\.name | string | 
action\_result\.data\.\*\.data\.address\.owner\.type | string | 
action\_result\.data\.\*\.data\.address\.rating | numeric | 
action\_result\.data\.\*\.data\.address\.webLink | string |  `url` 
action\_result\.data\.\*\.data\.emailAddress\.address | string |  `email` 
action\_result\.data\.\*\.data\.emailAddress\.confidence | numeric | 
action\_result\.data\.\*\.data\.emailAddress\.dateAdded | string | 
action\_result\.data\.\*\.data\.emailAddress\.description | string | 
action\_result\.data\.\*\.data\.emailAddress\.id | numeric | 
action\_result\.data\.\*\.data\.emailAddress\.lastModified | string | 
action\_result\.data\.\*\.data\.emailAddress\.owner\.id | numeric | 
action\_result\.data\.\*\.data\.emailAddress\.owner\.name | string | 
action\_result\.data\.\*\.data\.emailAddress\.owner\.type | string | 
action\_result\.data\.\*\.data\.emailAddress\.rating | numeric | 
action\_result\.data\.\*\.data\.emailAddress\.webLink | string |  `url` 
action\_result\.data\.\*\.data\.file\.confidence | numeric | 
action\_result\.data\.\*\.data\.file\.dateAdded | string | 
action\_result\.data\.\*\.data\.file\.description | string | 
action\_result\.data\.\*\.data\.file\.id | numeric | 
action\_result\.data\.\*\.data\.file\.lastModified | string | 
action\_result\.data\.\*\.data\.file\.md5 | string |  `hash`  `md5` 
action\_result\.data\.\*\.data\.file\.owner\.id | numeric | 
action\_result\.data\.\*\.data\.file\.owner\.name | string | 
action\_result\.data\.\*\.data\.file\.owner\.type | string | 
action\_result\.data\.\*\.data\.file\.rating | numeric | 
action\_result\.data\.\*\.data\.file\.sha1 | string |  `hash`  `sha1` 
action\_result\.data\.\*\.data\.file\.sha256 | string |  `hash`  `sha256` 
action\_result\.data\.\*\.data\.file\.size | numeric | 
action\_result\.data\.\*\.data\.file\.webLink | string |  `url` 
action\_result\.data\.\*\.data\.host\.confidence | numeric | 
action\_result\.data\.\*\.data\.host\.dateAdded | string | 
action\_result\.data\.\*\.data\.host\.description | string | 
action\_result\.data\.\*\.data\.host\.dns\_active | string | 
action\_result\.data\.\*\.data\.host\.hostName | string |  `domain` 
action\_result\.data\.\*\.data\.host\.id | numeric | 
action\_result\.data\.\*\.data\.host\.lastModified | string | 
action\_result\.data\.\*\.data\.host\.owner\.id | numeric | 
action\_result\.data\.\*\.data\.host\.owner\.name | string | 
action\_result\.data\.\*\.data\.host\.owner\.type | string | 
action\_result\.data\.\*\.data\.host\.rating | numeric | 
action\_result\.data\.\*\.data\.host\.webLink | string | 
action\_result\.data\.\*\.data\.host\.whois\_active | string | 
action\_result\.data\.\*\.data\.url\.confidence | numeric | 
action\_result\.data\.\*\.data\.url\.dateAdded | string | 
action\_result\.data\.\*\.data\.url\.description | string | 
action\_result\.data\.\*\.data\.url\.id | numeric | 
action\_result\.data\.\*\.data\.url\.lastModified | string | 
action\_result\.data\.\*\.data\.url\.owner\.id | numeric | 
action\_result\.data\.\*\.data\.url\.owner\.name | string | 
action\_result\.data\.\*\.data\.url\.owner\.type | string | 
action\_result\.data\.\*\.data\.url\.rating | numeric | 
action\_result\.data\.\*\.data\.url\.text | string | 
action\_result\.data\.\*\.data\.url\.webLink | string |  `url` 
action\_result\.data\.\*\.status | string | 
action\_result\.summary | string | 
action\_result\.summary\.attribute\_added | boolean | 
action\_result\.summary\.indicator\_created/updated | boolean | 
action\_result\.summary\.total\_objects | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt ip'
Hunt an IP and retrieve any available information

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to hunt | string |  `ip`  `ipv6` 
**owner** |  optional  | Indicator Owner within ThreatConnect | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.parameter\.owner | string | 
action\_result\.data\.\*\.data\.address\.\*\.confidence | numeric | 
action\_result\.data\.\*\.data\.address\.\*\.dateAdded | string | 
action\_result\.data\.\*\.data\.address\.\*\.description | string | 
action\_result\.data\.\*\.data\.address\.\*\.id | numeric | 
action\_result\.data\.\*\.data\.address\.\*\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.data\.address\.\*\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.data\.address\.\*\.lastModified | string | 
action\_result\.data\.\*\.data\.address\.\*\.ownerName | string | 
action\_result\.data\.\*\.data\.address\.\*\.rating | numeric | 
action\_result\.data\.\*\.data\.address\.\*\.webLink | string |  `url` 
action\_result\.data\.\*\.data\.resultCount | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.summary\.total\_objects | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt file'
Hunt a file hash and retrieve available information

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | File hash \(md5, sha1, sha256\) | string |  `hash`  `md5`  `sha1`  `sha256` 
**owner** |  optional  | Indicator Owner within ThreatConnect | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `hash`  `md5`  `sha1`  `sha256` 
action\_result\.parameter\.owner | string | 
action\_result\.data\.\*\.data\.file\.\*\.confidence | numeric | 
action\_result\.data\.\*\.data\.file\.\*\.dateAdded | string | 
action\_result\.data\.\*\.data\.file\.\*\.description | string | 
action\_result\.data\.\*\.data\.file\.\*\.id | numeric | 
action\_result\.data\.\*\.data\.file\.\*\.lastModified | string | 
action\_result\.data\.\*\.data\.file\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.data\.file\.\*\.ownerName | string | 
action\_result\.data\.\*\.data\.file\.\*\.rating | numeric | 
action\_result\.data\.\*\.data\.file\.\*\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.data\.file\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.data\.file\.\*\.webLink | string |  `url` 
action\_result\.data\.\*\.data\.resultCount | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.summary\.total\_objects | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt email'
Hunt an email and retrieve available information

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** |  required  | Email address | string |  `email` 
**owner** |  optional  | Indicator Owner within ThreatConnect | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.email | string |  `email` 
action\_result\.parameter\.owner | string | 
action\_result\.data\.\*\.data\.emailAddress\.\*\.address | string |  `email` 
action\_result\.data\.\*\.data\.emailAddress\.\*\.confidence | numeric | 
action\_result\.data\.\*\.data\.emailAddress\.\*\.dateAdded | string | 
action\_result\.data\.\*\.data\.emailAddress\.\*\.description | string | 
action\_result\.data\.\*\.data\.emailAddress\.\*\.id | numeric | 
action\_result\.data\.\*\.data\.emailAddress\.\*\.lastModified | string | 
action\_result\.data\.\*\.data\.emailAddress\.\*\.ownerName | string | 
action\_result\.data\.\*\.data\.emailAddress\.\*\.rating | numeric | 
action\_result\.data\.\*\.data\.emailAddress\.\*\.webLink | string |  `url` 
action\_result\.data\.\*\.data\.resultCount | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.summary\.total\_objects | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt domain'
Hunt a domain and retrieve available information

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain or URL name | string |  `url`  `domain` 
**owner** |  optional  | Indicator Owner within ThreatConnect | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `url`  `domain` 
action\_result\.parameter\.owner | string | 
action\_result\.data\.\*\.data\.host\.\*\.confidence | numeric | 
action\_result\.data\.\*\.data\.host\.\*\.dateAdded | string | 
action\_result\.data\.\*\.data\.host\.\*\.description | string | 
action\_result\.data\.\*\.data\.host\.\*\.hostName | string |  `domain` 
action\_result\.data\.\*\.data\.host\.\*\.id | numeric | 
action\_result\.data\.\*\.data\.host\.\*\.lastModified | string | 
action\_result\.data\.\*\.data\.host\.\*\.ownerName | string | 
action\_result\.data\.\*\.data\.host\.\*\.rating | numeric | 
action\_result\.data\.\*\.data\.host\.\*\.webLink | string |  `url` 
action\_result\.data\.\*\.data\.resultCount | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.summary\.total\_objects | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt url'
Hunt a URL and retrieve available information

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to find | string |  `url` 
**owner** |  optional  | Indicator Owner within ThreatConnect | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.owner | string | 
action\_result\.parameter\.url | string |  `url` 
action\_result\.data\.\*\.data\.resultCount | numeric | 
action\_result\.data\.\*\.data\.url\.\*\.confidence | numeric | 
action\_result\.data\.\*\.data\.url\.\*\.dateAdded | string | 
action\_result\.data\.\*\.data\.url\.\*\.description | string | 
action\_result\.data\.\*\.data\.url\.\*\.id | numeric | 
action\_result\.data\.\*\.data\.url\.\*\.lastModified | string | 
action\_result\.data\.\*\.data\.url\.\*\.ownerName | string | 
action\_result\.data\.\*\.data\.url\.\*\.rating | numeric | 
action\_result\.data\.\*\.data\.url\.\*\.text | string |  `url` 
action\_result\.data\.\*\.data\.url\.\*\.text | string | 
action\_result\.data\.\*\.data\.url\.\*\.webLink | string |  `url` 
action\_result\.data\.\*\.status | string | 
action\_result\.summary\.total\_objects | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 