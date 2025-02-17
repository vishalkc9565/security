## VIM advanced commands

```
:args **/*    " This recursively finds all files in current and subdirectories
:argdo        " Executes the following command on all files in the args list
```
- find all 200 responses:
```
:args **/*
:argdo g/^HTTP.*200/p
```
- Analyse output from matches
```This sequence:
:args **/*
:argdo g/^HTTP/y A    " Yanks (copies) all HTTP lines to register 'a'
:new                  " Creates new buffer
:put a               " Pastes content from register 'a'
```

`
:sort /HTTP\/[0-9]*/  " This sorts based on the status code number
`

```
:vimgrep /<pattern>/ **/*     " Search all files
:copen                      " Open quickfix window
```