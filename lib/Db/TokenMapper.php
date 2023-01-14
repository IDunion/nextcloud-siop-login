<?php

namespace OCA\OIDCLogin\Db;

use OCP\IDBConnection;
use OCP\AppFramework\Db\QBMapper;

class TokenMapper extends QBMapper
{
    public function __construct(IDBConnection $db)
    {
        parent::__construct($db, 'ssilogin_tokens', Token::class);
    }

    public function find(string $presentationID)
    {
        $qb = $this->db->getQueryBuilder();

        $qb->select('*')
            ->from($this->getTableName())
            ->where($qb->expr()->eq('presentation_id', $qb->createNamedParameter($presentationID)));

        return $this->findEntity($qb);
    }
}
