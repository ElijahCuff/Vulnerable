<?php
header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");

$device = getDevice("os","name");
$browser = getDevice("browser","name")." ".getDevice("browser","version");
$low = false;

if (hasParam('low'))
{
   $low = ( $_GET['low'] == true);
}
if ($low)
{
if (strpos($device,".") !== false)
{
     $end = strpos($device,".");
     $out = substr($device,0,$end);
     $device = $out;
}
if (strpos($browser,".") !== false)
{
     $end = strpos($browser, ".");
     $out = substr($browser, 0, $end);
     $browser = $out;
}
}




$device_vulns = getVulns($device);
$browser_vulns = getVulns($browser);

     $total_vulns = count($device_vulns)+count($browser_vulns);

           
           header("HTTP/1.1 200 OK");
           http_response_code(200); 
           $responseArray = array(
             $device => $device_vulns,
             $browser => $browser_vulns,
            );
           echo json_encode($responseArray,JSON_PRETTY_PRINT); 
           exit();


function getVulns($query)
{

$priors = 'https://raw.githubusercontent.com/offensive-security/exploitdb/master/';
$file = file('https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv');
  $listHtml = "";
  $vulnArr = array();
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
      
            $vulnArr[$count] = $exploitFile;
            $count++;
           
              }; 
         };
  return $vulnArr;
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
function hasParam($param) 
{
   if (array_key_exists($param, $_POST))
    {
       return array_key_exists($param, $_POST);
    } else
    {
      return array_key_exists($param, $_GET);
    }
}
?>
