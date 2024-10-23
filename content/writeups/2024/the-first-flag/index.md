+++
title = "The First Flag"
description = "Entry challenge!"
layout = "writeup"
time_spent = "2-5 mins"
tools_used = "Browser, Base64 decoder"
date = "2024-10-23"
+++



The first flag was hidden in plain sight. The instruction pointed you to the [rules](https://tribectf.cs.wm.edu/rules) page. 

You had to look up the source from the browser, and search for flag. 
![Page Source of Rules](/writeups/2024/the-first-flag/image.png)



You would end up getting this snippet. 

```html
<div style=display:none>Hint: Decode me to find the flag format!
dHJpYmVjdGZ7eW91cl9mbGFnX2hlcmV9
</div>
```

You could then use any Base64 decoder to get the flag format. 
![Base64 Decoder](/writeups/2024/the-first-flag/image-1.png)