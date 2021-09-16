use tagtagyeah; -- local
-- use heroku_acb493180552729; -- heroku ClearDB
-- use eij8pzwnprvffh1t; -- heroku JawsDB
drop table tag_table;
create table tag_table(
	id int not null primary key,
    user_id int not null,
	name varchar(50) not null,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
drop table user_table;
create table user_table(
	id int not null primary key,
    uuid char(20) not null,
    name varchar(20) not null,
    password varchar(100) not null,
    email varchar(100) not null,
    expire_uuid_at DATETIME NOT NULL,
    authorized BIT(1) NOT NULL DEFAULT false,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
drop table unit_table;
create table unit_table(
	id int not null primary key,
    user_id int not null,
    name varchar(100) not null,
    url varchar(200) not null,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
drop table unit_tag;
create table unit_tag(
	unit_id int not null,
    tag_id int not null,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    index unit_tag_index (unit_id,tag_id),
    unique (unit_id, tag_id)
);
insert into tag_table (id,user_id,name) values
(1,0,"tag1"),(2,0,"tag2"),(3,0,"tag3"),(4,0,"tag4"),(5,0,"tag5");
insert into user_table (id,uuid,name,password,email,expire_uuid_at) values
(0,"12345678901234567890","user0","pass","email",DATE_ADD(NOW(), INTERVAL 1 DAY));
insert into unit_table (id,user_id,name,url) values
(1,0,"testname1",""),(2,0,"testname2","testurl2"),(3,0,"","testurl3");
insert into unit_tag (unit_id,tag_id) values
(1,1),(1,2),(1,3),(1,4),(2,2),(2,5),(3,2);