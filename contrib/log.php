<?php

$path='log';
$lines = array();
$peers = array();
$ajax = FALSE;

function render_row ($d, $component, $pid, $level, $msg, $c)
{
  global $ajax;
  global $peers;
  if (!$ajax && $level == "DEBUG")
    return;

  list($comp,$peer) = explode (',', preg_replace ('/(.*)-(\d*)/', '\1,\2', $component));
  $peer = array_key_exists ($peer, $peers) ? $peers[$peer] : $peer;
  $date = $d ? $d->format('Y-m-d'). $d->format('H:i:s') : "";
  echo "<tr class=\"$level $peer\" id=\"$c\">";
  echo "<td class=\"date\"><small>$date</td>";
  echo '<td class="usec"><small>';
  echo $d ? $d->format('u') : "";
  echo '</small></td>';
  echo "<td class=\"comp\">$comp</td><td class=\"peer\">$peer</td>";
  echo "<td class=\"level\">$level</td><td>$msg&nbsp;</td>";
  if ($level != "DEBUG")
  {
    echo '<td><div class="btn-group"><button class="btn btn-xs btn-default btn-showup"><span class="glyphicon glyphicon-chevron-up"></span></button>';
    echo '<button class="btn btn-xs btn-default btn-showdown"><span class="glyphicon glyphicon-chevron-down"></span></button></div></td>';
//     echo '</td>';
  }
  else
    echo '<td></td>';
  echo '</tr>';
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
  global $peers;
  $a = explode (' ', $line);
  if (count($a) < 6)
    return;
  $date = DateTime::createFromFormat ("M d H:i:s-u", implode (' ', array_slice ($a, 0, 3)));
  $component = $a[3];
  $level = $a[4];
  $msg = implode (' ', array_slice ($a, 5));

  if (FALSE !== strpos($line, "STARTING SERVICE")) {
    $id = preg_replace ("/.*\[(....)\].*\n/", '\1', $line);
    $pid = preg_replace ("/.*[a-z-]*-([0-9]*).*\n/", '\1', $line);
    $peers[$pid] = $id;
  }

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
	if (!$start || $c >= $start) {
	  process ($line, $c);
	}
	$c++;
	if ($stop && $c > $stop)
	  break;
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
/*       color:#444; */
    }
    table {
      margin-top: 40px;
      font-size:12px;
      border-collapse:collapse;
    }
    .alert {
      display: none;
      position: fixed;
      width: 75%;
      left: 50%;
      margin: 5% 0 0 -37.5%;
    }
    .btn-toolbar {
      position: fixed;
      top: 0px;
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
    .btn-group {
      min-width: 48px;
    }
    table.table tbody tr td {
      padding: 0px 0px 0px 4px;
      margin-bottom: 0px;
    }
  </style>
</head>


<body>
<div class="btn-toolbar" role="toolbar">
  <div class="btn-group">
    <button id="ERROR" class="btn btn-danger btn-showlevel"><span class="glyphicon glyphicon-fire"></span> Error</button>
    <button id="WARNING" class="btn btn-warning btn-showlevel"><span class="glyphicon glyphicon-exclamation-sign"></span> Warning</button>
    <button id="INFO" class="btn btn-info btn-showlevel active"><span class="glyphicon glyphicon glyphicon-info-sign"></span> Info</button>
    <button id="DEBUG" class="btn btn-default btn-showlevel"><span class="glyphicon glyphicon glyphicon-wrench"></span> Debug</button>
  </div>
  <div class="btn-group">
    <?php foreach($peers as $pid=>$id): ?>
    <button id="<?php echo $id ?>" class="btn btn-default btn-showpeer active"><?php echo $id ?></button>
    <?php endforeach ?>
    <button id="btn-showall" class="btn btn-default">All</button>
    <button id="btn-shownone" class="btn btn-default">None</button>
  </div>
</div>
<div id="msg" class="alert alert-success"></div>
<table class="table">
  <thead>
  <tr>
    <th>Date Time</th>
    <th>uSec</th>
    <th>Comp</th>
    <th>Peer</th>
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
      $("tbody > tr").hide();
      $(".btn-showlevel").removeClass("active");
      $("#"+level).addClass("active");
      for (var index = 0; index < types.length; ++index) {
        $(".btn-showpeer.active").each(function(){
          $("."+types[index]+"."+this.id).show();
        });
	if (types[index] == level)
	  return;
      }
    }

    function shownone()
    {
      $(".btn-showpeer").removeClass("active");
      $("tbody > tr").hide();
    }

    function showall()
    {
      $(".btn-showpeer:not(.active)").each(function(){showpeer(this.id)});
    }

    function showpeer (peer)
    {
      $("#"+peer).toggleClass("active");
      if ($("#"+peer).hasClass("active")) {
        for (var index = 0; index < types.length; ++index) {
          var className = "." + types[index] + "." + peer;
          $(className).show();
          if ($("#"+types[index]).hasClass("active"))
            return;
        }
      } else {
        $("."+peer).hide();
      }
    }

    function load_debug (btn, up)
    {
      var tr = $(btn).parents("tr");
      var level;
      var pos = parseInt(tr.attr("id"));
      var first = pos + 1;
      var last = pos - 1;
      for (var index = 0; index < types.length; ++index) {
        if (tr.hasClass(types[index]))
        {
          level = types[index];
          break;
        }
      }
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
      $(".btn-showup").on ("click", function(){ load_debug(this, true) });
      $(".btn-showdown").on ("click", function(){ load_debug(this, false) });
      $(".btn-showlevel").on ("click", function(){ showlevel(this.id) });
      $(".btn-showpeer").on ("click", function(){ showpeer(this.id) });
      $("#btn-showall").on ("click", function(){ showall() });
      $("#btn-shownone").on ("click", function(){ shownone() });
    });
  </script>
</body>
</html>
