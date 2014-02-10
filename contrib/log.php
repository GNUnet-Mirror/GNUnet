<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  
  <title>GNUnet log view</title>

  <!-- Latest compiled and minified Bootstrap CSS -->
  <link rel="stylesheet" href="//netdna.bootstrapcdn.com/bootstrap/3.1.0/css/bootstrap.min.css">
  <!-- Optional theme -->
  <link rel="stylesheet" href="//netdna.bootstrapcdn.com/bootstrap/3.1.0/css/bootstrap-theme.min.css">

  <style>
    body {
      font-family: arial,sans-serif;
      color:#444;
    }
/*    a {
      text-decoration: none;
      color:#000;
    }*/
    table {
      font-size:12px;
      border-collapse:collapse;
    }
    .level {
      display: none;
    }
    .DEBUG {
      background-color:#CCC;
    }

  </style>
</head>


<body>

<table class="table">
  <tr>
    <th>Date Time</th>
    <th>uSec</th>
    <th>Comp</th>
    <th class="level">Level</th>
    <th>Message</th>
    <th></th>
  </tr>
<?php

$path='log';

function render_row ($d, $component, $pid, $level, $msg)
{
  $date = $d->format('Y-m-d'). '<br />' . $d->format('H:i:s');
  echo "<tr class=\"$level\">";
  echo "<td class=\"date\">$date</td>";
  echo '<td class="usec">';
  echo $d->format('u');
  echo '</td>';
  echo "<td class=\"comp\">$component</td><td class=\"level\">$level</td><td>$msg&nbsp;</td>";
  echo '<td><button class="btn btn-xs btn-default btn-show"><span class="glyphicon glyphicon-plus"></span></button>';
  echo '<button class="btn btn-xs btn-default btn-hide"><span class="glyphicon glyphicon-minus"></span></button></td></tr>';
  $olddate = $date;
} 

function process ($line)
{
  $a = explode (' ', $line);
  $date = DateTime::createFromFormat ("M d H:i:s-u", implode (' ', array_slice ($a, 0, 3)));
  $component = $a[3];
  $level = $a[4];
  $msg = implode (' ', array_slice ($a, 5));
  
  render_row ($date, $component, 0, $level, $msg);
}


$handle = @fopen($path, 'r');
if ($handle) {
    while (($line = fgets($handle)) !== false) {
        process ($line);
    }
} else {
   echo "<div class=\"alert alert-danger\">Error opening file $path.</div>";
}

?>

</table>
  <!-- jQuery -->
  <script src="http://code.jquery.com/jquery-1.10.1.min.js"></script>
  <!-- Latest compiled and minified Bootstrap JavaScript -->
  <script src="//netdna.bootstrapcdn.com/bootstrap/3.1.0/js/bootstrap.min.js"></script>

  <script>

    function show (btn)
    {
      var tr = $(btn).parents("tr");
      tr.nextUntil("."+tr.attr("class")).show();
      return;
    }

    function hide (btn)
    {
      var tr = $(btn).parents("tr");
      tr.nextUntil("."+tr.attr("class")).hide();
      return;
    }

    $(function() {
      $(".DEBUG").hide();
      $(".btn-show").on ("click", function(){ show(this) });
      $(".btn-hide").on ("click", function(){ hide(this) });
      console.log( "ready!" );
    });
  </script>
</body>
</html>
