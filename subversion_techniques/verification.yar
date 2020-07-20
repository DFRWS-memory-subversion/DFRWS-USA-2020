rule token_string {

    strings:
        $s1 = "AAAAAAAAAAAAAAAAAA_what.the.eyes.see.and.the.ears.hear..the.mind.believes_AAAAAAAAAAAAAAAAAA" ascii

    condition:
        all of them
}
