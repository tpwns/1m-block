#include "db.h"

/*host이름과 db파일명을 전달받아 파일안에 host가 존재하는지 반환하는 함수*/
bool db_query_host(std::string host, std::string dbname)
{
    sqlite3* db;
    sqlite3_stmt* res;
    char *err_msg = 0;
    bool isblock=false;
    
    int rc = sqlite3_open(dbname.c_str(), &db);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(1);
    }
    
    std::string sql = "select idx from tab1 where host = '";
    sql += host;
    sql += "'";
    //printf("%s\n",sql.c_str());

    //sql쿼리를 바이트코드로 컴파일, (DB핸들러, 쿼리문, 쿼리문길이, 쿼리핸들러, 0)
    rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &res, 0);    
    if (rc != SQLITE_OK) 
    {
        fprintf(stderr, "Failed to fetch data: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(1);
    }
    
    //sqlite3_prepare로 컴파일된 코드를 실행
    rc = sqlite3_step(res); 
    if (rc == SQLITE_ROW)   //쿼리의 결과가 존재하는 경우
    {
        isblock = true;       //host를 block
    }
    
    sqlite3_finalize(res);  //핸들 정리
    sqlite3_close(db);  //DB닫기
    
    return isblock;
}


