CREATE DEFINER = CURRENT_USER TRIGGER `Dionaea`.`connections_AFTER_INSERT` AFTER INSERT ON `connections` FOR EACH ROW
while new.connection_root is null
do
UPDATE connections SET connection_root = connection WHERE connection = new.connection AND new.connection_root IS NULL;
END while
