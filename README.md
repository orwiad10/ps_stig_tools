# ps_stig_tools

Here are some poorly written tools for STIG automations. 

The STIG duplicator works off of a CSV file of pre-compiled comments and VulnIDs. That means you have to do at least one check list fully by hand to get the CSV export for stig viewer.
You can then use one of the OS or app scripts to do the "manual checks", that’s any check that isn’t done by SCAP. So between the PS script and SCAP, that should cover most if not all checks. So after verifying output, you can in good conscious just duplicate the STIG check list based on previous known good comments.

A lot of the code is organization dependent so it just may not work for you. if it doesn’t work, go ahead and edit it.

Also be aware of deltas. The STIGS change from time to time so you could be running checks you no longer need or be missing new checks that have come out. i try to keep up with this but inevitably I miss things.

The Stig_suite is a big group of different functions that attempts to encompass the full workflow from stig downloads to a completed check list. Ive uploaded the menubased version right now, i may upload a more formal version of it that is more parameter based and can accept lists of devices instead of doing one at a time, this version is really just a prototype.

If you need any assistance or have question, you can message me on Reddit under the same username.

DISCLAIMER: Some checks in the manual scripts are only "good enough" on accuracy and functionallity. please review the code and result becuase if you fail your ATO because of me, i warned you.
