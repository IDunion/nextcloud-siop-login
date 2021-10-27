<?php

namespace OCA\OIDCLogin\Migration;

use Closure;
use OCP\DB\Types;
use OCP\DB\ISchemaWrapper;
use OCP\Migration\SimpleMigrationStep;
use OCP\Migration\IOutput;


class Version000000Date20211026230200 extends SimpleMigrationStep {
       
    /**
    * @param IOutput $output
    * @param Closure $schemaClosure The `\Closure` returns a `ISchemaWrapper`
    * @param array $options
    * @return null|ISchemaWrapper
    */
    public function changeSchema(IOutput $output, Closure $schemaClosure, array $options) {
        /** @var ISchemaWrapper $schema */
        $schema = $schemaClosure();

        if (!$schema->hasTable('oidclogin_request_uris')) {
            $table = $schema->createTable('oidclogin_request_uris');
            $table->addColumn('id', Types::INTEGER, [
                'autoincrement' => true,
                'notnull' => true,
            ]);
            $table->addColumn('request_uri', Types::STRING, [
                'notnull' => true,
                'length' => 200
            ]);
            $table->addColumn('request_object', Types::TEXT, [
                'notnull' => true,
                'default' => ''
            ]);
            $table->addColumn('creation_timestamp', Types::DATETIME, [
				'notnull' => false,
			]);

            $table->addIndex(['request_uri', 'creation_timestamp'], 'oidclogin_request_uris_index');
        }
        return $schema;
    }
}