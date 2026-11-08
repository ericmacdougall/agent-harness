#!/bin/bash
ssh -o ConnectTimeout=8 -o BatchMode=yes ah-mac-mini 'find /Users /home /opt -maxdepth 6 -path "*/.git/config" 2>/dev/null | xargs grep -l t2-course 2>/dev/null | head'
