CREATE EXTENSION unaccent;

-- must have a UTF8 database
SELECT getdatabaseencoding();
SET client_encoding TO 'KOI8';

SELECT unaccent('foobar');
SELECT unaccent('£ΜΛΑ');
SELECT unaccent('³φιλ');

SELECT unaccent('unaccent', 'foobar');
SELECT unaccent('unaccent', '£ΜΛΑ');
SELECT unaccent('unaccent', '³φιλ');

SELECT ts_lexize('unaccent', 'foobar');
SELECT ts_lexize('unaccent', '£ΜΛΑ');
SELECT ts_lexize('unaccent', '³φιλ');

CREATE TEXT SEARCH CONFIGURATION unaccent(
						COPY=russian
);

ALTER TEXT SEARCH CONFIGURATION unaccent ALTER MAPPING FOR
	asciiword, word WITH unaccent MAP russian_stem;

SELECT to_tsvector('unaccent', 'foobar ³φιλι £ΜΛΙ');
