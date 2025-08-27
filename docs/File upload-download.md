
Uploading function first sends file name and then it sends the data

if the file is from implant it will be save in `./uploads_implant` if it is from the operator the file will be save in `./uploads_operator` 

```json
{
	"file_name":"xxx",
}
```

will have two commands from the operator
1. For viewing files in `uploads_implant` 
	- Command will be `view-files implants`
2. for viewing files in the `./uplaods_operator`
	- `view-files operator`

```json
{
	"Info":"files",
	"option":"upload" or "download",
	"folder":"implants" # or "operator"
}
```