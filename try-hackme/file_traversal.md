

- Search for filename or related arguments where filepath is present
- Run the attack through intruder and use payload from Extension generated (Psycopath). This does not have `/etc/passwd`
- double filter of `..` and `/` to replace it. it may be done one more time so payload like `....//....//` is good to bypass it
- any number of repetition might not be enough, so url encode one or twice or json encoding might byass it
- sometime prefixed paths are required, so need to do traversal to do that `/image?filename=/var/www/images/../../../etc/passwd` where `/var/www/images` must be present
- An application may require the user-supplied filename to end with an expected file extension, such as .png Use null byte in this case `filename=../../../etc/passwd%00.png`
- Use the payload `../small-script-payload/path_traversal_payload/`



- run `dirsearch` for the traversal file payload. <TODO: add command here> 
- On windows, the dirsearch is somewhat different but its available in payload. `On Windows, both ../ and ..\ are valid directory traversal sequences.`
- `/usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt` contains different file payloads
- Create a payload file which contains all of this