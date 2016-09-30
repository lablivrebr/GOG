/**
 * Adição da coluna "idOauth" do tipo "String" na tabela "tbusuario", levando em consideração situações que esse campo venha números ou letras. 
 */
ALTER TABLE tbusuario ADD COLUMN idOauth character varying(255);