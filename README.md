## Rocking Teenage Combo (Zappa for Pirates)

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/ambv/black)


*Rocking Teenage Combo currently works for me but is under heavy construction so it 
most likely won't work for you at this point. Best to wait for an official stable 
release which can be properly supported*

Rocking Teenage Combo deploys python 3.7 Flask 
applications to AWS Lambda serverless instances.
 
Originally forked from [this](https://github.com/purificant/Zappa/tree/py37)
fork of [Zappa](https://github.com/Miserlou/Zappa) (pre-merge), Rocking Teenage Combo 
has diverged so far from the source that it is maintained as a separate application 
(although it still tracks commits to the Zappa source tree).

RTC works just like Zappa ([docs here](https://github.com/Miserlou/Zappa)) with the 
following changes:
 
- can be called with 'rtc' or 'zappa'
- reimplemented copytree
- package wheels are automatically downloaded, built in a Python 3.7 Lambda Docker 
container, and saved to an S3 bucket
- add 'rtc restart [stage]' command (being backported from [SplashStand](https://splashtand.com))
- reorganized codebase into it's logical components
- [CrackerJack'd](https://gitlab.com/lesleslie/crackerjack) codebase 
(supports Python 3.7+ only)
- no Django support (currently)
- no multi-session support (currently)
- no policy support (currently)
- more (this doc a work in progress)
