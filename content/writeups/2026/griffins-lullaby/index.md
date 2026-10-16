+++
title = "Griffin's Lullaby"
description = "Not every Griffin has wings; one of them wrote a lullaby for his son."
layout = "writeup"
category = "Miscellaneous"
points = "500 pts"
time_spent = "1-2 hours"
tools_used = "Sonic Visualiser or Audacity (spectrogram), CyberChef (Vigenère Decode)"
date = "2026-10-15"
+++

You got one file, `Lullaby.mp3`: about 75 seconds of piano playing Brahms' Lullaby twice. The piano is not the message. A quiet flute plays underneath it, and the flags hide in the flute.

### Step 0: Find the second instrument

Listen with headphones, or open the file in Sonic Visualiser or Audacity and switch to a spectrogram (log frequency, about 200–1000 Hz). The loud notes follow the lullaby. Under them, a fainter line of notes does not belong to the tune. It plays twice:

- 0:18–0:35, under the second half of the first time through
- 0:41–0:56, under the first half of the second time through

Tip: the piano part is identical both times, so compare the same spot in the two passes. Anything that shows up in one pass and not the other is the flute.

### Step 1: Write down the notes

The flute plays one note per beat (80 BPM), and some beats are silent. Writing one note or rest per beat gives two lines:

```
Line 1: G#5 F4 B4 F5 D#5 rest C4 F#5 B3 G#4 E4 A#4 C#5 rest B4 A#5 B3 G#4 rest D4 F#4 A#5
Line 2: A3 F4 F#4 E5 G#4 F#5 A#3 rest A#4 F5 C#4 A4 E4 rest A#3 C5 rest E4 A5 A3
```

### Step 2: Notes to letters

The flute stays between A3 and A#5: 26 half steps, one for each letter. Start at A3 (220 Hz) = `A` and count up one letter per half step:

| A | B | C | D | E | F | G | H | I | J | K | L | M |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A3 | A#3 | B3 | C4 | C#4 | D4 | D#4 | E4 | F4 | F#4 | G4 | G#4 | A4 |
| **N** | **O** | **P** | **Q** | **R** | **S** | **T** | **U** | **V** | **W** | **X** | **Y** | **Z** |
| A#4 | B4 | C5 | C#5 | D5 | D#5 | E5 | F5 | F#5 | G5 | G#5 | A5 | A#5 |

A silent beat is an underscore:

```
Line 1: XIOUS_DVCLHNQ_OZCL_FJZ
Line 2: AIJTLVB_NUEMH_BP_HYA
```

Neither line reads as English, so there is a cipher on top. The description is a riddle that points to a word, so try Vigenère with that word as the key.

### Step 3: The obvious key is a trap

The tune is Brahms' Lullaby, so `BRAHMS` is the first key to try. Vigenère Decode in CyberChef, key `BRAHMS`, on line 1:

```
WRONG_LULLABY_NICE_TRY
```

`tribectf{wrong_lullaby_nice_try}` is a fake flag, and it says so. `BRAHMS` on line 2 gives junk.

### Step 4: Find the right Griffin

Read the description again: "Not every Griffin has wings; one of them wrote a lullaby for his son." This Griffin is not the W&M mascot, and the lullaby is not Brahms' (he wrote his for a friend's baby). It's Merv Griffin, who created *Jeopardy!*. He wrote the show's "Think!" music, the 30 seconds that play during Final Jeopardy, as a lullaby for his son Tony. It was first called "A Time for Tony".

The key is `JEOPARDY`. 

### Step 5: Decrypt

Vigenère Decode, key `JEOPARDY`, on line 2. Underscores do not use up key letters, which is CyberChef's default:

```
REVELEY_PLAYS_BY_EAR
```

Reveley is the name of W&M's Griffin mascot.

### Flag

```
tribectf{reveley_plays_by_ear}
```
