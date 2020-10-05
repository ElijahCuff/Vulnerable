<?php

$device = getDevice("os","name");
$browser = getDevice("browser","name")." ".getDevice("browser","version");

if (strpos($device,".") !== false)
{
     $end = strpos($device,".");
     $out = substr($device,0,$end);
     $device = $out;
}


$device_vulns = getVulns($device);
$browser_vulns = getVulns($browser);

if ($device_vulns > 0 || $browser_vulns > 0 )
  {
     $total_vulns = $device_vulns+$browser_vulns;
     echo $total_vulns." Possible Security Issues with your current ".$device.", ".$browser;
 }
 else
{
  echo "redirect to end address here";
  
}


function getVulns($query)
{

$priors = 'https://raw.githubusercontent.com/offensive-security/exploitdb/master/';
$file = file($priors.'files_exploits.csv');
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
            $count++;
              }; 
         };
  return $count;
}





function clean_input($data) {
  $data = trim($data);
  $data = stripslashes($data);
  $data = htmlspecialchars($data);
  return $data;
}



function getDevice($category, $name) 
{
$apiKey = "5985c982a526da775e017b7479e8f738";

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
$out = $api_result[$category][$name];

return $out;
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
