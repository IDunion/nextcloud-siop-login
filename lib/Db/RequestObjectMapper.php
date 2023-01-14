<?php

namespace OCA\OIDCLogin\Db;

use OCP\IDBConnection;
use OCP\AppFramework\Db\QBMapper;

class RequestObjectMapper extends QBMapper
{
    public function __construct(IDBConnection $db)
    {
        parent::__construct($db, 'ssilogin_request_uris', RequestObject::class);
    }

    public function find(string $requestUri)
    {
        $qb = $this->db->getQueryBuilder();

        $qb->select('*')
            ->from($this->getTableName())
            ->where($qb->expr()->eq('request_uri', $qb->createNamedParameter($requestUri)));

        return $this->findEntity($qb);
    }
}
