# Install on WordPress

## 1. Schema + social tags (5 min)
- Install the free plugin **"Insert Headers and Footers"** (WPCode).
- Go to **Code Snippets → Header & Footer**.
- Paste the entire contents of `schema-jsonld.html` into the **Header** box.
- Paste the entire contents of `og-tags.html` into the **Header** box too.
- Save.

## 2. llms.txt + robots.txt (5 min)
- Use **File Manager** (in your hosting cPanel) or an FTP app.
- Upload `llms.txt` to the `public_html` folder (same folder as `wp-config.php`).
- If your kit has `robots.txt`: upload it to `public_html` too, overwriting the old one —
  but first check the old one for lines your SEO plugin added and merge them.
- If your kit has `robots-addendum.txt`: read it first — your site may be blocking all crawlers.

## 3. Sitemap
Rank Math / Yoast SEO generate one automatically at `yoursite.com/sitemap_index.xml`.
Submit it in Google Search Console.

## 4. Booking
If your audit flagged the action surface: add online booking with a plugin like
Amelia (appointments) or WooCommerce (ordering). This is the highest-leverage fix.
