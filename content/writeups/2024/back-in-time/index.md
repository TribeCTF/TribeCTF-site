+++
title = "Back In Time"
description = ""
layout = "writeup"
category = "Forensics"
points = "300pts"
time_spent = "5 mins"
tools_used = "Git"
date = "2024-11-02"
+++


This challenge named `Back In Time` was one of the easier challenges in the Forensics category.
For this challenge, you were given a single file `BackInTime.zip`.

After unzipping the file and taking a look at it, we can see that there is a single directory named `src_repo`. 
If we enter into this repo, we can see many different folder, one of which is named `.git`. This indicates that we are
looking at a git repo and this challenge is likely some kind of git forensics challenge. 

So the first thing we can do is take a look around the repo and check the commit history. Using the following command,
`git log` we get the following git history. 

```shell
commit 0edf042c3c002179cd7a70184d9648737c2b1b5f (HEAD -> main)
Author: Nicolas Janis <Nicolas.d.janis@gmail.com>
Date:   Wed Oct 2 14:08:22 2024 -0400

    remove: REDACTED INFORMATION

commit 63c9ffef884182db12db12377208d3e3cdffcb1c
Author: Nicolas Janis <Nicolas.d.janis@gmail.com>
Date:   Wed Oct 2 14:07:37 2024 -0400

    add: Config options

commit 3a58baa3643157e8f00c12e7190ee8023abdbde3
Author: Nicolas Janis <Nicolas.d.janis@gmail.com>
Date:   Wed Oct 2 14:05:08 2024 -0400

    add: Initial information
```

From this, we can see that in the previous commit "REDACTED INFORMATION" was removed. So, why don't we roll back the
commit to see what this information might have been. Using the `git reset HEAD~1` command we can. Running the command 
we get:

```shell
❯ git reset HEAD~1
Unstaged changes after reset:
D	secrets/config.ini
```

From this we can see, that a file named `secrets/config.ini` was deleted in the last commit. Running 
`git restore secrets` we can restore the file. Then we can read it using `cat secrets/config.ini`.

```ini
[ISC4]
name = Integrated Science Center 4
location = William & Mary, Williamsburg, VA
description = State-of-the-art science research facility supporting Chemistry, Biology, Physics, Data Science, and Engineering.
height = 6 stories
sustainability = LEED-certified
energy_efficiency = High-performance systems, eco-friendly materials

[Facilities]
quantum_computing_lab = True
automated_lab_systems = True
rooftop_observatory = True
collaborative_spaces = True

[Departments]
chemistry = True
biology = True
physics = True
data_science = True
engineering = True

[CollaborativeSpaces]
open_layout = True
cross_disciplinary_projects = True
student_research_opportunities = True

[Sustainability]
leed_certification = Platinum
energy_efficient_systems = True
eco_friendly_materials = True

[Contact]
building_manager = Dr. Jane Doe
email = janedoe@wm.edu
phone = +1 (757) 221-1234

[Repository]
blueprints = /path/to/blueprints
scripts = /path/to/scripts
config_files = /path/to/configurations
last_update = 2024-09-28

[API]
key = tribectf{git_forensics_is_a_science}
```

And just like that we have our flag:

`tribectf{git_forensics_is_a_science}`