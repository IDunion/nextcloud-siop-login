<?php

namespace OCA\OIDCLogin\Migration;

use Closure;
use OCP\DB\Types;
use OCP\DB\ISchemaWrapper;
use OCP\Migration\SimpleMigrationStep;
use OCP\Migration\IOutput;

class Version000000Date20211004160300 extends SimpleMigrationStep {

        /**
    * @param IOutput $output
    * @param Closure $schemaClosure The `\Closure` returns a `ISchemaWrapper`
    * @param array $options
    * @return null|ISchemaWrapper
    */
    public function changeSchema(IOutput $output, Closure $schemaClosure, array $options) {
        /** @var ISchemaWrapper $schema */
        $schema = $schemaClosure();

        if (!$schema->hasTable('oidclogin_tokens')) {
            $table = $schema->createTable('oidclogin_tokens');
            $table->addColumn('id', Types::INTEGER, [
                'autoincrement' => true,
                'notnull' => true,
            ]);
            $table->addColumn('nonce', Types::STRING, [
                'notnull' => true,
                'length' => 200
            ]);
            $table->addColumn('id_token', Types::TEXT, [
                'notnull' => true,
                'default' => ''
            ]);
            $table->addColumn('vp_token', Types::TEXT, [
                'notnull' => true,
                'default' => ''
            ]);
            $table->addColumn('used', Types::BOOLEAN, [
                'notnull' => false,
                'default' => false
            ]);
            $table->addColumn('creation_timestamp', Types::DATETIME, [
				'notnull' => false,
			]);

            // $table->setPrimaryKey(['nonce']);
            $table->addIndex(['nonce', 'creation_timestamp'], 'oidclogin_tokens_index');
        }
        return $schema;
    }

}

?>