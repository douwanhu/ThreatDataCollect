-- MySQL Script generated by MySQL Workbench
-- Wed Jul 26 16:09:04 2017
-- Model: New Model    Version: 1.0
-- MySQL Workbench Forward Engineering

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL,ALLOW_INVALID_DATES';

-- -----------------------------------------------------
-- Schema Dionaea
-- -----------------------------------------------------
DROP SCHEMA IF EXISTS `Dionaea` ;

-- -----------------------------------------------------
-- Schema Dionaea
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `Dionaea` DEFAULT CHARACTER SET utf8 ;
USE `Dionaea` ;

-- -----------------------------------------------------
-- Table `Dionaea`.`connections`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Dionaea`.`connections` ;

CREATE TABLE IF NOT EXISTS `Dionaea`.`connections` (
  `connection` INT NOT NULL AUTO_INCREMENT,
  `connection_type` VARCHAR(45) NULL,
  `connection_transport` VARCHAR(45) NULL,
  `connection_protocol` VARCHAR(45) NULL,
  `connection_timestamp` INT NULL,
  `connection_root` INT NULL,
  `connection_parent` INT NULL,
  `local_host` VARCHAR(45) NULL,
  `local_port` INT NULL,
  `remote_host` VARCHAR(45) NULL,
  `remote_hostname` TINYTEXT NULL,
  `remote_port` INT NULL,
  PRIMARY KEY (`connection`),
  INDEX `connections_type_idx` (`connection_type` ASC),
  INDEX `connections_timestamp_idx` (`connection_timestamp` ASC),
  INDEX `connections_root_idx` (`connection_root` ASC),
  INDEX `connections_parent_idx` (`connection_parent` ASC),
  INDEX `connections_local_host_idx` (`local_host` ASC),
  INDEX `connections_local_port_idx` (`local_port` ASC),
  INDEX `connections_remote_host_idx` (`remote_host` ASC))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `Dionaea`.`dcerpcbinds`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Dionaea`.`dcerpcbinds` ;

CREATE TABLE IF NOT EXISTS `Dionaea`.`dcerpcbinds` (
  `dcerpcbind` INT NOT NULL,
  `connection` INT NULL,
  `dcerpcbind_uuid` LONGTEXT NULL,
  `dcerpcbind_transfersyntax` LONGTEXT NULL,
  INDEX `dcerpcbinds_connection_idx` (`connection` ASC),
  PRIMARY KEY (`dcerpcbind`))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `Dionaea`.`dcerpcrequests`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Dionaea`.`dcerpcrequests` ;

CREATE TABLE IF NOT EXISTS `Dionaea`.`dcerpcrequests` (
  `dcerpcrequest` INT NOT NULL,
  `connection` INT NULL,
  `dcerpcrequest_uuid` LONGTEXT NULL,
  `dcerpcrequest_opnum` INT NULL,
  PRIMARY KEY (`dcerpcrequest`),
  INDEX `dcerpcrequests_opnum_idx` (`dcerpcrequest_opnum` ASC),
  INDEX `dcerpcrequests_connection_idx` (`connection` ASC))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `Dionaea`.`dcerpcserviceops`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Dionaea`.`dcerpcserviceops` ;

CREATE TABLE IF NOT EXISTS `Dionaea`.`dcerpcserviceops` (
  `dcerpcserviceop` INT NOT NULL,
  `dcerpcservice` INT NULL,
  `dcerpcserviceop_opnum` INT NULL,
  `dcerpcserviceop_name` TINYTEXT NULL,
  `dcerpcserviceop_vuln` TINYTEXT NULL,
  PRIMARY KEY (`dcerpcserviceop`),
  UNIQUE INDEX `dcerpcservice_UNIQUE` (`dcerpcservice` ASC),
  UNIQUE INDEX `dcerpcserviceop_opnum_UNIQUE` (`dcerpcserviceop_opnum` ASC))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `Dionaea`.`dcerpcservices`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Dionaea`.`dcerpcservices` ;

CREATE TABLE IF NOT EXISTS `Dionaea`.`dcerpcservices` (
  `dcerpcservice` INT NOT NULL,
  `dcerpcservice_uuid` LONGTEXT NULL,
  `dcerpcservice_name` TINYTEXT NULL,
  PRIMARY KEY (`dcerpcservice`))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `Dionaea`.`downloads`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Dionaea`.`downloads` ;

CREATE TABLE IF NOT EXISTS `Dionaea`.`downloads` (
  `download` INT NOT NULL,
  `connection` INT NULL,
  `download_url` LONGTEXT NULL,
  `download_md5_hash` LONGTEXT NULL,
  PRIMARY KEY (`download`))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `Dionaea`.`emu_profiles`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Dionaea`.`emu_profiles` ;

CREATE TABLE IF NOT EXISTS `Dionaea`.`emu_profiles` (
  `emu_profile` INT NOT NULL,
  `connection` INT NULL,
  `emu_profile_json` LONGTEXT NULL,
  PRIMARY KEY (`emu_profile`))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `Dionaea`.`emu_services`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Dionaea`.`emu_services` ;

CREATE TABLE IF NOT EXISTS `Dionaea`.`emu_services` (
  `emu_serivce` INT NOT NULL,
  `connection` INT NULL,
  `emu_service_url` LONGTEXT NULL,
  PRIMARY KEY (`emu_serivce`),
  INDEX `emu_services_connection_idx` (`connection` ASC))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `Dionaea`.`logins`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Dionaea`.`logins` ;

CREATE TABLE IF NOT EXISTS `Dionaea`.`logins` (
  `login` INT NOT NULL,
  `login_username` TINYTEXT NULL,
  `login_password` TINYTEXT NULL,
  PRIMARY KEY (`login`))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `Dionaea`.`mqtt_fingerprints`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Dionaea`.`mqtt_fingerprints` ;

CREATE TABLE IF NOT EXISTS `Dionaea`.`mqtt_fingerprints` (
  `mqtt_fingerprint` INT NOT NULL,
  `connection` INT NULL,
  `mqtt_fingerprint_clientid` TINYTEXT NULL,
  `mqtt_fingerprint_willtopic` TINYTEXT NULL,
  `mqtt_fingerprint_willmessage` LONGTEXT NULL,
  `mqtt_fingerprint_username` TINYTEXT NULL,
  `mqtt_fingerprint_password` TINYTEXT NULL,
  PRIMARY KEY (`mqtt_fingerprint`),
  INDEX `mqtt_fingerprints_connection_idx` (`connection` ASC))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `Dionaea`.`mqtt_publish_commands`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Dionaea`.`mqtt_publish_commands` ;

CREATE TABLE IF NOT EXISTS `Dionaea`.`mqtt_publish_commands` (
  `mqtt_publish_command` INT NOT NULL,
  `connection` INT NULL,
  `mqtt_publish_command_topic` TINYTEXT NULL,
  `mqtt_publish_command_message` LONGTEXT NULL,
  PRIMARY KEY (`mqtt_publish_command`),
  INDEX `mqtt_publish_commands_connection_idx` (`connection` ASC))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `Dionaea`.`mqtt_subscribe_commands`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Dionaea`.`mqtt_subscribe_commands` ;

CREATE TABLE IF NOT EXISTS `Dionaea`.`mqtt_subscribe_commands` (
  `mqtt_subscribe_command` INT NOT NULL,
  `connection` INT NULL,
  `mqtt_subscribe_command_messageid` TINYTEXT NULL,
  `mqtt_subscribe_command_topic` TINYTEXT NULL,
  PRIMARY KEY (`mqtt_subscribe_command`),
  INDEX `mqtt_subscribe_commands_connection_idx` (`connection` ASC))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `Dionaea`.`mssql_commands`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Dionaea`.`mssql_commands` ;

CREATE TABLE IF NOT EXISTS `Dionaea`.`mssql_commands` (
  `mssql_command` INT NOT NULL,
  `connection` INT NULL,
  `mssql_command_status` TINYTEXT NULL,
  `mssql_command_cmd` LONGTEXT NULL,
  PRIMARY KEY (`mssql_command`))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `Dionaea`.`mssql_fingerprints`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Dionaea`.`mssql_fingerprints` ;

CREATE TABLE IF NOT EXISTS `Dionaea`.`mssql_fingerprints` (
  `mssql_fingerprint` INT NOT NULL,
  `connection` INT NULL,
  `mssql_fingerprint_hostname` TINYTEXT NULL,
  `mssql_fingerprint_appname` TINYTEXT NULL,
  `mssql_fingerprint_cltintname` TINYTEXT NULL,
  PRIMARY KEY (`mssql_fingerprint`),
  INDEX `mssql_fingerprints_connection_idx` (`connection` ASC))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `Dionaea`.`mysql_command_args`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Dionaea`.`mysql_command_args` ;

CREATE TABLE IF NOT EXISTS `Dionaea`.`mysql_command_args` (
  `mysql_command_arg` INT NOT NULL,
  `mysql_command` INT NULL,
  `mysql_command_arg_index` FLOAT NOT NULL,
  `mysql_command_arg_data` LONGTEXT NOT NULL,
  PRIMARY KEY (`mysql_command_arg`),
  INDEX `mysql_command_args_command_idx` (`mysql_command` ASC))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `Dionaea`.`mysql_command_ops`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Dionaea`.`mysql_command_ops` ;

CREATE TABLE IF NOT EXISTS `Dionaea`.`mysql_command_ops` (
  `mysql_command_op` INT NOT NULL,
  `mysql_command_cmd` INT NOT NULL,
  `mysql_command_op_name` TINYTEXT NOT NULL,
  PRIMARY KEY (`mysql_command_op`))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `Dionaea`.`mysql_commands`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Dionaea`.`mysql_commands` ;

CREATE TABLE IF NOT EXISTS `Dionaea`.`mysql_commands` (
  `mysql_command` INT NOT NULL,
  `connection` INT NULL,
  `mysql_command_cmd` FLOAT NOT NULL,
  PRIMARY KEY (`mysql_command`),
  INDEX `mysql_commands_connection_idx` (`connection` ASC))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `Dionaea`.`offers`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Dionaea`.`offers` ;

CREATE TABLE IF NOT EXISTS `Dionaea`.`offers` (
  `offer` INT NOT NULL,
  `connection` INT NULL,
  `offer_url` LONGTEXT NULL,
  PRIMARY KEY (`offer`),
  INDEX `offers_connection_idx` (`connection` ASC))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `Dionaea`.`p0fs`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Dionaea`.`p0fs` ;

CREATE TABLE IF NOT EXISTS `Dionaea`.`p0fs` (
  `p0f` INT NOT NULL,
  `connection` INT NULL,
  `p0f_genre` LONGTEXT NULL,
  `p0f_uptime` INT NULL,
  `p0f_link` TINYTEXT NULL,
  `p0f_detail` LONGTEXT NULL,
  `p0f_tos` TINYTEXT NULL,
  `p0f_dist` INT NULL,
  `p0f_nat` INT NULL,
  `p0f_fw` INT NULL,
  PRIMARY KEY (`p0f`),
  INDEX `p0fs_uptime_idx` (`p0f_uptime` ASC),
  INDEX `p0fs_connection_idx` (`connection` ASC))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `Dionaea`.`resolves`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Dionaea`.`resolves` ;

CREATE TABLE IF NOT EXISTS `Dionaea`.`resolves` (
  `resolve` INT NOT NULL,
  `connection` INT NULL,
  `resolve_hostname` TINYTEXT NULL,
  `resolve_type` TINYTEXT NULL,
  `resolve_result` LONGTEXT NULL,
  PRIMARY KEY (`resolve`))
ENGINE = InnoDB;

USE `Dionaea`;

DELIMITER $$

USE `Dionaea`$$
DROP TRIGGER IF EXISTS `Dionaea`.`connections_AFTER_INSERT` $$
USE `Dionaea`$$
CREATE DEFINER = CURRENT_USER TRIGGER `Dionaea`.`connections_AFTER_INSERT` AFTER INSERT ON `connections` FOR EACH ROW
while new.connection_root is null
do
UPDATE connections SET connection_root = connection WHERE connection = new.connection AND new.connection_root IS NULL;
END while$$


DELIMITER ;

SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;