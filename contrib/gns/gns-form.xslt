<?xml version="1.0" encoding="UTF-8"?>
<xsl:transform xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

	<xsl:output method="html" indent="yes" />

	<xsl:template match="form">
		<html>
			<head>
				<title>Create your GNU Name System Business Card</title>
				<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0" />
				<link href="bootstrap.min.css" rel="stylesheet" />
			</head>
			<body>
				<!--<script src="js/jquery-2.0.3.min.js"></script>-->
				<!--<script src="js/bootstrap.min.js"></script>-->
				<div class="container">
					<h1>GNU Name System Business Card</h1>
					<p>
						Please fill in the information below to generate your business card.
					</p>
					<form class="form-horizontal" name="gnsinput" action="submit.pdf" method="get" accept-charset="utf-8">
						<xsl:apply-templates />
						<div class="form-group">
							<div class="col-sm-offset-2 col-sm-10">
								<input class="btn btn-submit" type="submit" />
							</div>
						</div>
					</form>
				</div>
			</body>
		</html>
	</xsl:template>

	<xsl:template match="group">
		<fieldset>
			<legend><!--<xsl:value-of select="@title" />--></legend>
			<xsl:apply-templates />
		</fieldset>
	</xsl:template>

	<xsl:template match="field">
		<div class="form-group">
			<label class="col-sm-2 control-label" for="{@id}"><xsl:value-of select="." />:</label>
			<div class="col-sm-10">
				<input class="col-sm-10 form-control" id="{@id}" name="{@id}" type="text" />
			</div>
		</div>
	</xsl:template>

</xsl:transform>
