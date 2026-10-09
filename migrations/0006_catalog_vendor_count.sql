-- Each vendor's products, most-affected first, so resolving a vendor name
-- reads only its top few products instead of every one (VENDOR_TOP_SQL).
-- The daily recount rewrites only counts that changed, so upkeep is about one
-- extra row written per changed product.
CREATE INDEX catalog_vendor_count ON catalog (vendor, count DESC, key) WHERE kind = 'product';
