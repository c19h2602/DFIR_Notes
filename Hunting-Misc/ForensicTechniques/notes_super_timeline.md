# Super Timeline Forensics Notes

> Paolo Coba | 04/03/2021

-------------------------------------------

## Resources
* [https://www.youtube.com/watch?v=sAvyRwOmE10](https://www.youtube.com/watch?v=sAvyRwOmE10)
* [https://plaso.readthedocs.io/en/latest/](https://plaso.readthedocs.io/en/latest/)
* [https://github.com/mark-hallman/plaso_filters](https://github.com/mark-hallman/plaso_filters)

## Log2timeline

Extract events from image files, storage media or devices, recurse directories. Creates a plaso storage file which can be analyzed with `pinfo` or `psort`.

### Generate timeline
* Use `psteal`
```bash
psteal.py --source <source image> -o <output format> -w <outfile>
```
* Use `log2timeline` and `psort`
```bash
log2timeline.py --storage_file <output> <source image>
psort.py -o <output format> -w <outfile> timeline.plaso
```

#### Customize output
* Check available parsers
```bash
log2timeline.py --parsers list
```
* Log2timeline filters: specify artifacts and artifact locations to look for
```bash
log2timeline.py -f <filter> --storage_file <plaso sqlite dump> <image>
```
* Can be combined
* Output will a SQLite database: need to run `psort` to change format. Can also specify date range to get events only for relevant period.
```bash
psort.py --output_time_zone UTC -o <output format> -w <outname> <plaso sqlite dump> "date > '<date>' AND date < '<date>'"
```

#### View Output
* Tool: [Timeline Explorer](https://ericzimmerman.github.io/#!index.md)