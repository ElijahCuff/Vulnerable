<?php
/**

Automatic Vulnerability Finder Version 2.0
- Accessing this script will search your device for vulnerabilities.
 
The idea of this script is to demonstrate how bots can use online databases to search for vulnerabilities.

Copyright 2020 WokeWorld. All Rights Reserved.

THIS SOFTWARE OR ANY PORTION THEREOF MAY NOT BE REPRODUCED, MODIFIED OR USED IN ANY MANNER WHATSOEVER WITHOUT THE EXPRESS WRITTEN PERMISSION FROM THE AUTHORS OR COPYRIGHT HOLDERS.

THIS SOFTWARE IS PROVIDED AS IS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
**/
// set API Key for userstack.com
$apiKey = "";


$device = getDevice("os","name");
/**
ACCEPTED Cat & Name for getDevice(cat,name);
Category  >  Name

ua	
type	
brand	
name	
url	
os > name	
os > code	
os > url	
os > family	
os > family_code	
os > family_vendor	
os > icon	
os > icon	
device > is_mobile_device	
device > type	
browser > name	
browser > version	
browser > version_major
browser > engine	
crawler > is_crawler	
crawler > category	
crawler > last_seen
**/



$load = urlDecode(cleancode($_GET['load']));
if (strpos($device,".") !== false)
{
     $end = strpos($device,".");
     $out = substr($device,0,$end);
     $device = $out;
}

$query = cleancode($_POST['device']);
if (!strlen($query)>0)
{
  $query = $device;
}




if (strlen($load) >0)
{
   // chosen load
   $lines = file($load);
   $html = "";
   foreach($lines as $line)
   {
    $html .= cleancode($line);
   }
   echo cleancode($html,true);
}
else
{
   if (strlen($query)>0)
    {

$priors = 'https://raw.githubusercontent.com/offensive-security/exploitdb/master/';
$file = file('https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv');
  $listHtml = "";
  $count = 0;
       foreach($file as $value) { 
         if(stristr($value,$query)){
            $items = explode(",", $value); 
            $date = $items[3];
            $id = $items[0];
            $author = $items[4];
            $local = $items[5];
            $os = $items[6];
            $name = cleancode(cleancode($items[2],true)).'...';
            $exploitDirectory = $items[1];
            $exploitFile = $priors.$items[1];

            $listHtml .= '<div align="left"><h3 class="mbr-light mbr-fonts-style display-5" align="left">'.($count+1).' - '.$author.' '.$local.'</h3><a class="btn btn-primary display-4" 
onclick=\'showPart("'.$exploitFile.'");\'>'.$name.'</a>
<br></div>';
            $count++;
              }; 
         };

    echo '
<!DOCTYPE html>
<html >
<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1, minimum-scale=1">
  <link rel="shortcut icon" href="assets/images/icon.png" type="image/x-icon">
  <meta name="description" content="Instant Device Vulnerability Scanner for Websites by WokeWorld©">
  <title>Vulnerable©</title>
  <link rel="stylesheet" href="assets/web/assets/mobirise-icons/mobirise-icons.css">
  <link rel="stylesheet" href="assets/tether/tether.min.css">
  <link rel="stylesheet" href="assets/bootstrap/css/bootstrap.min.css">
  <link rel="stylesheet" href="assets/bootstrap/css/bootstrap-grid.min.css">
  <link rel="stylesheet" href="assets/bootstrap/css/bootstrap-reboot.min.css">
  <link rel="stylesheet" href="assets/theme/css/style.css">
  <link rel="stylesheet" href="assets/mobirise/css/mbr-additional.css" type="text/css">
</head>
<body>
  <section class="header1 cid-rRnxKlpfV6" id="header1-4">

    

    

    <div class="container">
        <div class="row justify-content-md-center">
            <div class="mbr-white col-md-10">
                <h1 class="mbr-section-title align-center mbr-bold pb-3 mbr-fonts-style display-1">Vulnerable©</h1>
                
                <p class="mbr-text align-center pb-3 mbr-fonts-style display-4">Instant device vulnerability scanner by WokeWorld©<br>Copyright © 2020 WokeWorld© All Rights Reserved.</p>
<div class="align-center">
<form action="" method="post">
        <input class="btn"  type="name" name="device" style="border-radius:10px;font-size:14px;" value="'.$query.'">
    </form>
</div>
    </div>
</div>

</div>
</section>
<section class="mbr-section info1 cid-rRnvQypYz7" id="info1-2">
    <div class="container" align="center">
        <div class="justify-content-center">
            <div class="title col-12 col-lg-7 col-md-6">
                <h1 class="mbr-bold mbr-fonts-style display-6">'.$count.'</h1><br>
                <div class="mbr-section-btnpy-4"><a class="btn btn-primary display-4" id="toggleButton" onclick="toggleText();">Hide List</a></div>
    
                
            </div>
        </div>
 <div class="container" align="left" >
<pre  class="pre-scrollable" style="white-space:pre;"><code id="vulArea" style="font-size:11px;max-height:200px;"></code></pre></div>
<h2 class="mbr-light display-5">Vulnerability List</h2>
<div id="textArea" style="height: calc(50vh);overflow: scroll;">

'.$listHtml.'

</div>
    </div>
</section>

<script>
var status = "hide";
function toggleText()
{
if (status == "show") {
document.getElementById("toggleButton").innerText = "Opening List";
}
else
{
document.getElementById("toggleButton").innerText = "Closing List";
}

setTimeout(function(){ 
    if (status == "show") {
        document.getElementById("textArea").style.display = "block";
        document.getElementById("toggleButton").innerText = "Hide List";
        status = "hide";
    } else if (status == "hide") {
        document.getElementById("textArea").style.display = "none"; 
        document.getElementById("toggleButton").innerText = "Show List";
        status = "show"
}
}, 10);
}

function showPart(url){
document.getElementById("vulArea").innerText = "Loading";
var xhr = new XMLHttpRequest();
xhr.open(\'GET\', url, true);
xhr.send();
xhr.onreadystatechange = processRequest;
function processRequest(e) {
    if (xhr.readyState == 4 && xhr.status == 200) {
       document.getElementById("vulArea").innerText = xhr.responseText;
    }
  }
}
</script>
  <script src="assets/web/assets/jquery/jquery.min.js"></script>
  <script src="assets/popper/popper.min.js"></script>
  <script src="assets/tether/tether.min.js"></script>
  <script src="assets/bootstrap/js/bootstrap.min.js"></script>
  <script src="assets/smoothscroll/smooth-scroll.js"></script>
  <script src="assets/theme/js/script.js"></script>
  
</body>
</html>



';
}
}
function clean_input($data) {
  $data = trim($data);
  $data = stripslashes($data);
  $data = htmlspecialchars($data);
  return $data;
}
function getDevice($category, $name) 
{
global $apiKey;
$useragent=$_SERVER['HTTP_USER_AGENT'];
$queryparams = http_build_query([
  'access_key' => $apiKey,
  'ua' => $useragent
]);

$ch = curl_init('http://api.userstack.com/detect?' . $queryparams);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

$json = curl_exec($ch);
curl_close($ch);

$api_result = json_decode($json, true);
return $api_result[$category][$name];
}

function cleancode($input, $isOutput = false)
{
$output = "";
 if (!$isOutput)
    {
      $output = filter_var($input, FILTER_SANITIZE_STRING);
    }
   else
    {
      $output = htmlspecialchars($input, ENT_COMPAT, 'UTF-8');
    }
 return $output;
}

?>
