# Install on a custom / other website

## 1. Schema + social tags
Paste the entire contents of `schema-jsonld.html` and `og-tags.html` into the
`<head>` section of every page (or your shared header template), just before
`</head>`. Replace any `REPLACE_WITH_` placeholders with your real info.

## 2. llms.txt + robots.txt
Upload both files to your site's **root folder** — the same folder that serves
`yoursite.com/`, so they're reachable at `yoursite.com/llms.txt` and
`yoursite.com/robots.txt`.

## 3. Sitemap
If you don't have one, generate it (most frameworks/CMSs have a plugin) and
reference it from robots.txt — your kit's robots.txt already includes the line.

## 4. Social image
Create a 1200×630px image, upload it as `og-image.jpg` to your root folder.

## 5. Booking / ordering
If your audit flagged the action surface, this is the highest-leverage fix:
embed your booking provider (Booksy, Vagaro, Calendly, Tock, OpenTable…) or
ordering flow directly on the homepage so an agent can complete it.
