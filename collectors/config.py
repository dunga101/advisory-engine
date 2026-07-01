# Verdict rubric constant (Section 6 of the build brief). KEV-listed/actively
# exploited always bypasses this and gets deploy_now regardless.
WAIT_DAYS = 5

# Field report source weight for the verdict engine's "wait" duration estimate
# (Section 6: "duration scaled to source weight and report count"). Ordering
# matches Section 5's stated source weight: microsoft_release_health > vendor_kb
# > community.
SOURCE_WEIGHT = {
    "microsoft_release_health": 3,
    "vendor_kb": 2,
    "community": 1,
}
