# Install on Squarespace

## 1. Schema + social tags (5 min)
- Go to **Settings → Advanced → Code Injection**.
- Paste the entire contents of `schema-jsonld.html` into the **Header** box.
- Paste `og-tags.html` there too.
- For the social image: **Settings → Social Links** won't do it — instead go to
  **Design → Social Image** (or per-page SEO settings) and upload a 1200×630 image.
- Save.

## 2. llms.txt + robots.txt
Squarespace doesn't allow arbitrary root files on most plans.
- **robots.txt**: Squarespace manages its own and doesn't block AI crawlers by default.
  No action needed unless your audit flagged a block.
- **llms.txt**: can't be served at `/llms.txt` on standard plans — skip it, it's a
  5-point hedge. Your schema markup carries the weight.
- **Sitemap**: automatic at `yoursite.com/sitemap.xml`. No action needed.

## 3. Booking
Squarespace Scheduling (formerly Acuity) — connect it and embed the scheduler on
your homepage. For restaurants: add Tock or OpenTable embed. Highest-leverage fix.
