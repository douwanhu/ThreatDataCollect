-- MySQL Script generated by Victor Dou
-- Wed Jul 19 16:33:56 2017
-- Model: New Model    Version: 1.0
-- Kaspersky Lab Inc.

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL,ALLOW_INVALID_DATES';

-- -----------------------------------------------------
-- Schema Honeypot
-- -----------------------------------------------------
-- DB for Cowrie honeypot
DROP SCHEMA IF EXISTS `Honeypot` ;

-- -----------------------------------------------------
-- Schema Honeypot
--
-- DB for Cowrie honeypot
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `Honeypot` DEFAULT CHARACTER SET utf8 ;
USE `Honeypot` ;

-- -----------------------------------------------------
-- Table `Honeypot`.`Cowrie`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Honeypot`.`Cowrie` ;

CREATE TABLE IF NOT EXISTS `Honeypot`.`Cowrie` (
  `id` INT NOT NULL,
  `session` VARCHAR(45) NULL,
  `eventid` VARCHAR(45) NULL,
  `timestamp` VARCHAR(45) NULL,
  `message` VARCHAR(1000) NULL,
  `username` VARCHAR(45) NULL,
  `password` VARCHAR(45) NULL,
  `system` VARCHAR(45) NULL,
  `src_ip` VARCHAR(45) NULL,
  `src_port` INT NULL,
  `dst_ip` VARCHAR(45) NULL,
  `dst_port` INT NULL,
  `input` VARCHAR(1000) NULL,
  PRIMARY KEY (`id`),
  INDEX `session_in` (`session` ASC),
  INDEX `eventid_in` (`eventid` ASC),
  INDEX `timestamp_in` (`timestamp` ASC),
  INDEX `message_in` (`message` ASC),
  INDEX `username_in` (`username` ASC),
  INDEX `password_in` (`password` ASC),
  INDEX `system_in` (`system` ASC),
  INDEX `src_ip_in` (`src_ip` ASC),
  INDEX `src_port_in` (`src_port` ASC),
  INDEX `dst_ip_in` (`dst_ip` ASC),
  INDEX `dst_port_in` (`dst_port` ASC),
  INDEX `input` (`input` ASC))
ENGINE = InnoDB;


SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;

alter table Cowrie change id id int auto_increment;
alter table Cowrie auto_increment=1 
