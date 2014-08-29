#!/bin/sh

curl --output book-data.zip http://media.wiley.com/product_ancillary/22/11187937/DOWNLOAD/9781118793725_download.zip
unzip -d book-data book-data.zip
