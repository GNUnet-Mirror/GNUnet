<?php

$path='log';
$lines = array();
$ajax = FALSE;

function render_row ($d, $component, $pid, $level, $msg, $c)
{
  global $ajax;
  if (!$ajax && $level == "DEBUG")
    return;
  $date = $d ? $d->format('Y-m-d'). '<br />' . $d->format('H:i:s') : "";
  echo "<tr class=\"$level\" id=\"$c\">";
  echo "<td class=\"date\"><small>$date</small></td>";
  echo '<td class="usec">';
  echo $d ? $d->format('u') : "";
  echo '</td>';
  echo "<td class=\"comp\">$component</td><td class=\"level\">$level</td><td>$msg&nbsp;</td>";
  if ($level != "DEBUG")
  {
    echo '<td><button class="btn btn-xs btn-default btn-showup"><span class="glyphicon glyphicon-chevron-up"></span></button>';
    echo '<button class="btn btn-xs btn-default btn-showdown"><span class="glyphicon glyphicon-chevron-down"></span></button></td></tr>';
  }
  else
    echo '<td></td></tr>';
}

function render_rows ()
{
  global $lines;
  foreach ($lines as $line) {
    render_row ($line[0], $line[1], $line[2], $line[3], $line[4], $line[5]);
  }
}

function process ($line, $c)
{
  global $lines;
  $a = explode (' ', $line);
  if (count($a) < 6)
    return;
  $date = DateTime::createFromFormat ("M d H:i:s-u", implode (' ', array_slice ($a, 0, 3)));
  $component = $a[3];
  $level = $a[4];
  $msg = implode (' ', array_slice ($a, 5));
  
  $lines[] = array ($date, $component, 0, $level, $msg, $c);
}

if (array_key_exists ('a', $_GET)) {
  $start = (int)$_GET['a'];
  $ajax= TRUE;
}
else
{
  $start = null;
}
if (array_key_exists ('z', $_GET)) {
  $stop = (int)$_GET['z'];
  $ajax= TRUE;
}
else
{
  $stop = null;
}
$t0 = microtime(true);
$handle = @fopen($path, 'r');
if ($handle) {
    $c = 0;
    while (($line = fgets($handle)) !== false) {
	if ((!$start || $c >= $start) && (!$stop || $c <= $stop)) {
	  process ($line, $c);
	}
	$c++;
    }
} else {
   echo "<div class=\"alert alert-danger\">Error opening file $path.</div>";
}

$t1 = microtime(true);
if ($start !== null || $stop !== null) {
  render_rows();
  die();
}
// echo $t1-$t0;

?>
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
    table {
      font-size:12px;
      border-collapse:collapse;
    }
    .alert {
      display: none;
      position: fixed;
      width: 75%;
      left: 50%;
      margin: 0 0 0 -37.5%;
    }
    .level {
      display: none;
    }
    .DEBUG {
      background-color:#CCC;
    }
    .WARNING {
      background-color:#EB9316;
    }
    .ERROR {
      background-color:#D2322D;
    }

  </style>
</head>


<body>
<div class="btn-toolbar" role="toolbar">
  <div class="btn-group">
    <button class="btn btn-danger btn-showerror"><span class="glyphicon glyphicon-fire"></span> Error</button>
    <button class="btn btn-warning btn-showwarn"><span class="glyphicon glyphicon-exclamation-sign"></span> Warning</button>
    <button class="btn btn-info btn-showinfo"><span class="glyphicon glyphicon glyphicon-info-sign"></span> Info</button>
    <button class="btn btn-default btn-showdebug"><span class="glyphicon glyphicon glyphicon-wrench"></span> Debug</button>
</div>
</div>
<div id="msg" class="alert alert-success"></div>
<table class="table">
  <thead>
  <tr>
    <th>Date Time</th>
    <th>uSec</th>
    <th>Comp</th>
    <th class="level">Level</th>
    <th>Message</th>
    <th></th>
  </tr>
  </thead>
  <tbody>
<?php render_rows(); ?>
  </tbody>
</table>
  <!-- jQuery -->
  <script src="http://code.jquery.com/jquery-1.10.1.min.js"></script>
  <!-- Latest compiled and minified Bootstrap JavaScript -->
  <script src="//netdna.bootstrapcdn.com/bootstrap/3.1.0/js/bootstrap.min.js"></script>

  <script>

    var types = ["ERROR", "WARNING", "INFO", "DEBUG"];
    var msg_timeout;

    function msg (content)
    {
      $("#msg").html(content);
      $("#msg").stop(true);
      $("#msg").fadeTo(100, 1).fadeTo(3000, 0.90).fadeOut(1000);
    }

    function showlevel (level)
    {
      $("tr").hide();
      for (var index = 0; index < types.length; ++index) {
	$("."+types[index]).show();
	if (types[index] == level)
	  return;
      }
    }

    function show (btn, up)
    {
      var tr = $(btn).parents("tr");
      var level = tr.attr("class");
      var pos = parseInt(tr.attr("id"));
      var first = pos + 1;
      var last = pos - 1;
      if (up) {
	if (parseInt(tr.prev().attr("id")) == last) {
	  msg ("Already loaded");
	  return;
	}
	first = parseInt(tr.prevAll("."+level).first().attr("id")) + 1;
	first = isNaN(first) ? 0 : first;
      } else {
	if (parseInt(tr.next().attr("id")) == first) {
	  msg ("Already loaded");
	  return;
	}
	last = parseInt(tr.nextAll("."+level).first().attr("id")) - 1;
      }
      if (first > last)
	return;
      $.ajax({
	url: document.location,
	data: { a: first, z: last }
      }).done(function ( resp ) {
	var loc = $("#"+(first-1));
	if (loc.length > 0)
	  loc.after(resp);
	else {
	  $("#"+(last+1)).before(resp);
	}
	msg("Done loading " + (last-first+1) + " lines.");
      });
      //tr.nextUntil("."+tr.attr("class")).show();
      
    }

    function hide (btn)
    {
      var tr = $(btn).parents("tr");
      tr.nextUntil("."+tr.attr("class")).hide();
    }

    $(function() {
      $(".btn-showup").on ("click", function(){ show(this, true) });
      $(".btn-showdown").on ("click", function(){ show(this, false) });
      $(".btn-showerror").on ("click", function(){ showlevel("ERROR") });
      $(".btn-showwarn").on ("click", function(){ showlevel("WARNING") });
      $(".btn-showinfo").on ("click", function(){ showlevel("INFO") });
      $(".btn-showdebug").on ("click", function(){ showlevel("DEBUG") });
    });
  </script>
</body>
</html>
