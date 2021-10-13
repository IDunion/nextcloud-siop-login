<?php

namespace OCA\OIDCLogin\Db;

use OCP\IDBConnection;
use OCP\AppFramework\Db\QBMapper;

class TokenMapper extends QBMapper {
    public function __construct(IDBConnection $db) {
        parent::__construct($db, 'oidclogin_tokens', Token::class);        
    }

    public function find(string $nonce) {
        $qb = $this->db->getQueryBuilder();

        $qb->select('*')
            ->from($this->getTableName())
            ->where($qb->expr()->eq('nonce', $qb->createNamedParameter($nonce)));

        return $this->findEntity($qb);
    }
}

?>