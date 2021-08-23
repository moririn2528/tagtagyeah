use tagtagyeah;
drop table tag_table;
create table tag_table(
	id int auto_increment not null primary key,
    user_id int not null,
	name varchar(50) not null,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
insert into tag_table (user_id,name) values (0,"test1");
select * from tag_table;
delete from tag_table where user_id = 0;
INSERT INTO tag_table (user_id,name) SELECT (0,"testA")
WHERE NOT EXISTS(SELECT id FROM tag_table WHERE user_id = 0 AND name = "testA");