# Install on Wix

## 1. Schema + social tags (5 min)
- Go to **Settings → SEO → SEO Settings** (site-level).
- Under **Advanced SEO settings**, paste the contents of `schema-jsonld.html`
  into the **Header Code** box.
- Paste `og-tags.html` there too. For the social image: **Settings → Social Share**
  lets you upload the preview image directly (1200×630px).
- Publish.

## 2. llms.txt + robots.txt
Wix doesn't allow uploading arbitrary files to the root on most plans.
Workarounds:
- **robots.txt**: Wix generates its own. Go to **Settings → SEO → Robots.txt Editor**
  (available on paid plans) and merge in the AI-friendly lines from your kit.
- **llms.txt**: if your plan can't serve it at `/llms.txt`, skip it — it's a 5-point
  hedge, not the core. Your schema markup carries the weight.
- **Sitemap**: Wix generates one automatically. No action needed.

## 3. Booking
Wix Bookings (appointments) or Wix Stores (ordering) — add the app, put the booking
widget on your homepage. This is the highest-leverage fix.
